/* The confidential and proprietary information contained in this repository may
*  only be used by a person authorised under and to the extent permitted
*  by a subsisting licensing agreement from ARM Limited or its affiliates.
*
*       (C) COPYRIGHT 2017 ARM Limited or its affiliates.
*           ALL RIGHTS RESERVED
*
*  This entire notice must be reproduced on all copies of this repository
*  and copies of this repository may only be made by a person if such person is
*  permitted to do so under the terms of a subsisting license agreement
*  from ARM Limited or its affiliates.
*/

#include <signal.h>

#include "mosquitto.h"

#include "common/constants.h"
#include "pt-client/pt_api.h"
#include "mbed-trace/mbed_trace.h"
#include "pt-example/client_config.h"
#include "pt-example_1520/pt_example_clip_1520.h"

#define TRACE_GROUP "clnt-example"

#include "jansson.h"

#include <pthread.h>
#include <semaphore.h>
#include <pthread.h>
#include <unistd.h>

struct connection *g_connection = NULL;

void lorapt_connection_ready_handler(struct connection *connection, void* ctx);
int lorapt_receive_write_handler(struct connection *connection,
                                 const char *device_id, const uint16_t object_id,
                                 const uint16_t instance_id, const uint16_t resource_id,
                                 const unsigned int operation,
                                 const uint8_t *value, const uint32_t value_size,
                                 void* userdata);
void lorapt_shutdown_handler(struct connection **connection, void *ctx);
volatile int lorapt_translator_started = 0;
pthread_t lorapt_thread;
struct mosquitto *g_mosq = NULL;

#define LORAPT_DEFAULT_LIFETIME 10000
#define BIT_32 32

typedef enum {
    SENSOR_TEMPERATURE,
    SENSOR_HUMIDITY,
    SENSOR_GPIO
} sensor_type_e;

/*
 * Bookkeeping to keep track of devices registered or "seen"
 */

typedef struct {
    ns_list_link_t link;
    pt_device_t* device;
} lorapt_device_t;

typedef struct {
    ns_list_link_t link;
    pt_device_t* device;    
    uint16_t object_id;
    uint16_t instance_id; 
    uint16_t resource_id;
    unsigned int operation;
    char session_id[BIT_32+1];
    char *value;
} write_session_t;
/**
 * \brief Structure to pass the protocol translator initialization
 * data to the protocol translator API.
 */
typedef struct protocol_translator_api_start_ctx {
    const char *hostname;
    int port;
} protocol_translator_api_start_ctx_t;
protocol_translator_api_start_ctx_t *global_pt_ctx;

typedef NS_LIST_HEAD(lorapt_device_t, link) lorapt_device_list_t;
typedef NS_LIST_HEAD(write_session_t, link) write_session_list_t;
bool protocol_translator_shutdown_handler_called = false;
lorapt_device_list_t *lorapt_devices = NULL;
write_session_list_t *session_list = NULL;

void gen_random(char *s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len]='\0';
}

void lorapt_add_device(pt_device_t *device) 
{
    lorapt_device_t *device_entry = (lorapt_device_t*) malloc(sizeof(lorapt_device_t));
    if (device_entry == NULL) {
        return;
    }
    device_entry->device = device;
    tr_info("Adding device to list");
    ns_list_add_to_end(lorapt_devices, device_entry);
}

int lorapt_device_exists(const char* deveui) 
{
    tr_info("Checking device '%s' exists", deveui);
    ns_list_foreach(lorapt_device_t, cur, lorapt_devices) {
        tr_info("====>Checking %s", cur->device->device_id);
        if (strncmp(cur->device->device_id, deveui, strlen(cur->device->device_id)) == 0) {
            return 1;
        }
    }
    return 0;
}

pt_device_t* find_device(const char* device_id)
{
    ns_list_foreach(lorapt_device_t, cur, lorapt_devices) {
        tr_info("Checking %s", cur->device->device_id);
        if (strlen(cur->device->device_id) == strlen(device_id) &&
            strncmp(cur->device->device_id, device_id, strlen(cur->device->device_id)) == 0) {
            return cur->device;
        }
    }
    return NULL;
}

int session_id_exists(const char* id) 
{
    tr_info("Checking session id '%s' exists", id);
    ns_list_foreach(write_session_t, cur, session_list) {
        tr_info("Checking %s", cur->session_id);
        if (strncmp(cur->session_id, id, strlen(cur->session_id)) == 0) {
            return 1;
        }
    }
    return 0;
}

write_session_t *find_session(const char* id) 
{
    ns_list_foreach(write_session_t, cur, session_list) {
        if (strlen(cur->session_id) == strlen(id) &&
            strncmp(cur->session_id, id, strlen(cur->session_id)) == 0) {
            return cur;
        }
    }
    return NULL;   
}

/*
 * Protocol translator's internal eventloop needs a thread to run in
 */
void* lorapt_translator_thread_routine(void *ctx)
{
    const protocol_translator_api_start_ctx_t *pt_start_ctx = (protocol_translator_api_start_ctx_t*) global_pt_ctx;
    protocol_translator_callbacks_t *pt_cbs = calloc(1, sizeof(protocol_translator_callbacks_t));
    pt_cbs->connection_ready_cb = lorapt_connection_ready_handler;
    pt_cbs->received_write_cb = lorapt_receive_write_handler;
    pt_cbs->connection_shutdown_cb = lorapt_shutdown_handler;

    pt_client_start(pt_start_ctx->hostname, pt_start_ctx->port, "testing-lora", pt_cbs,
                    (void*) ctx, &g_connection);
    free(pt_cbs);
    return NULL;
}

void lorapt_start_translator(struct mosquitto *mosq)
{
    if (lorapt_translator_started == 0) {
        pthread_create(&lorapt_thread, NULL, &lorapt_translator_thread_routine, (void *) mosq);
        lorapt_translator_started = 1;
    }
}

/*
 * Callback handlers for PT operations
 */

void lorapt_device_register_success_handler(const char *device_id, void *ctx)
{
    if (ctx) {
        printf("A device register finished successfully.\n");
        printf("deveui %s\n", (char*)ctx);
        //lorapt_add_device((const char*)ctx); //skip
    }
    free(ctx);
}

void lorapt_device_register_failure_handler(const char *device_id, void *ctx)
{
    printf("A device register failed.\n");
    free(ctx);
}

void lorapt_device_write_success_handler(const char *device_id, void *ctx)
{
    printf("A device write finished successfully.\n");
    free(ctx);
}

void lorapt_device_write_failure_handler(const char *device_id, void *ctx)
{
    printf("A device write failed.\n");
    free(ctx);
}

void lorapt_protocol_translator_registration_success_handler(void *ctx)
{
    lorapt_translator_started = 1;
    printf("LoRa translator registered successfully.\n");
}

void lorapt_protocol_translator_registration_failure_handler(void *ctx)
{
    struct mosquitto *mosq = (struct mosquitto *) ctx;

    printf("LoRa translator registration failed.\n");
    mosquitto_disconnect(mosq);
}

void lorapt_connection_ready_handler(struct connection *connection, void* ctx)
{
    pt_register_protocol_translator(g_connection, lorapt_protocol_translator_registration_success_handler, lorapt_protocol_translator_registration_failure_handler, ctx);
}

void mqtt_pushlish_message(const char *device_id, const uint16_t object_id, const uint8_t* value, char* session_id)
{
    int rc;
    int qos = 0;
    bool retain = false;
    char pushlish_topic[50]= {0} ;
    char *payload = NULL;
    json_t *json_message = NULL;
    int gpio_value;

    switch(object_id)
    {
        case 3201:
                gpio_value = atoi((char *)value);
                if (gpio_value == 0 || gpio_value == 1)
                {
                    gen_random(session_id, BIT_32);
                    json_message = json_pack("{s{s{s[{sbss}]}}sssisisssssi}", "susiCommData", "sensorIDList", "e", "bv", gpio_value, "n", "SenHub/SenData/GPIO1", \
                                        "sessionID", session_id, "commCmd" , 525, "requestID", 0,"agentID", "", "handlerName", "SenHub", "sendTS" ,1466088605);
                }
                else
                {
                    tr_err("mqtt_pushlish_message: set wrong value");        
                }
            break;

        default:
            tr_err("mqtt_pushlish_message: type error");
            break;
    }

    if (json_message != NULL)
    {
        payload = json_dumps(json_message, JSON_COMPACT | JSON_SORT_KEYS);
        sprintf(pushlish_topic, "/cagent/admin/%s/agentcallbackreq", device_id);
        rc = mosquitto_publish(g_mosq, NULL, pushlish_topic, strlen(payload), (uint8_t *) payload, qos, retain);
        if (rc)
        {
            tr_err("mosquitto_publish failed");
        }
        json_decref(json_message);
        free(payload);
    }
    else
    {
        tr_err("mqtt_pushlish_message: json_message is null");
    }
}

void write_sensor_value(const char* session_id)
{
    write_session_t* temp_session = find_session(session_id);
    pt_device_t *device = temp_session->device;
    pt_object_t *object = pt_device_find_object(device, temp_session->object_id);
    pt_object_instance_t *instance = pt_object_find_object_instance(object, temp_session->instance_id);
    pt_resource_opaque_t *resource = pt_object_instance_find_resource(instance, temp_session->resource_id);

    if (!device || !object || !instance || !resource) {
        tr_warn("No match for device \"%s/%d/%d/%d\" on write action.",
                temp_session->device->device_id, temp_session->object_id, temp_session->instance_id, temp_session->resource_id);
        return;
    }

    /* Check if resource supports operation */
    if (!(resource->operations & temp_session->operation)) {
        tr_warn("Operation %d tried on resource \"%s/%d/%d/%d\" which does not support it.",
                temp_session->operation, temp_session->device->device_id, temp_session->object_id, temp_session->instance_id, temp_session->resource_id);
        return;
    }    

    if (temp_session->operation & OPERATION_WRITE && resource->operations & OPERATION_WRITE) {
        if (resource->value_size != strlen(temp_session->value)) {
            tr_info("Writing new value to \"%s/%d/%d/%d\".",
                    temp_session->device->device_id, temp_session->object_id, temp_session->instance_id, temp_session->resource_id);

        }
    } else if (temp_session->operation & OPERATION_EXECUTE && resource->operations & OPERATION_EXECUTE) {
            tr_info("OPERATION_EXECUTE\n");
    }

    free(resource->value);
    resource->value_size = strlen(temp_session->value);
    resource->value = malloc(resource->value_size);
    memcpy(resource->value, temp_session->value, resource->value_size);
    char* deveui_ctx = strdup(device->device_id);
    pt_write_value(g_connection, device, device->objects, lorapt_device_write_success_handler, lorapt_device_write_failure_handler, deveui_ctx);
}

int lorapt_receive_write_handler(struct connection *connection,
                                 const char *device_id, const uint16_t object_id,
                                 const uint16_t instance_id, const uint16_t resource_id,
                                 const unsigned int operation,
                                 const uint8_t *value, const uint32_t value_size,
                                 void* userdata)
{
    pt_device_t *device = find_device(device_id);
    pt_object_t *object = pt_device_find_object(device, object_id);
    pt_object_instance_t *instance = pt_object_find_object_instance(object, instance_id);
    pt_resource_opaque_t *resource = pt_object_instance_find_resource(instance, resource_id);

    if (!device || !object || !instance || !resource) {
        tr_err("No match for device \"%s/%d/%d/%d\" on write action.",
                device_id, object_id, instance_id, resource_id);
        return 1;
    }

    /* Check if resource supports operation */
    if (!(resource->operations & operation)) {
        tr_err("Operation %d tried on resource \"%s/%d/%d/%d\" which does not support it.",
                operation, device_id, object_id, instance_id, resource_id);
        return 1;
    }    

    if (operation & OPERATION_WRITE && resource->operations & OPERATION_WRITE) {
        if (resource->value_size != value_size) {
            tr_info("Writing new value to \"%s/%d/%d/%d\".",
                    device_id, object_id, instance_id, resource_id);

        }
    } else if (operation & OPERATION_EXECUTE && resource->operations & OPERATION_EXECUTE) {
            tr_info("OPERATION_EXECUTE");
    }

    if (memcmp(resource->value, value, strlen((char*)value)) != 0) 
    {
        // free(resource->value);
        // resource->value = malloc(value_size);
        // memcpy(resource->value, value, value_size);
        // resource->value_size = value_size;
        char session_id[BIT_32+1] = {0};
        mqtt_pushlish_message(device_id, object_id, value, session_id);

        write_session_t *write_access = (write_session_t*) malloc(sizeof(write_session_t));
        write_access->device = device;
        write_access->object_id = object_id;
        write_access->instance_id = instance_id;
        write_access->resource_id = resource_id;
        write_access->operation = operation;

        memcpy(write_access->session_id, session_id, BIT_32+1);
        write_access->value = (char*) malloc(sizeof(char) * strlen((char*)value));
        memset(write_access->value, 0, strlen(write_access->value));
        memcpy(write_access->value, (char*)value, strlen((char*)value));

        printf("Adding session to list\n");
        ns_list_add_to_end(session_list, write_access);        
        //pt_write_value(connection, device, device->objects, lorapt_device_write_success_handler, lorapt_device_write_failure_handler, (void*) device_id);
    }
    else
    {
        tr_err("Writing the same value to \"%s/%d/%d/%d\" on write action.",
                device_id, object_id, instance_id, resource_id);
        return 1;
    }

    return 0;
}

void lorapt_shutdown_handler(struct connection **connection, void *userdata)
{
    struct mosquitto *mosq = (struct mosquitto *) userdata;
    printf("Shutting down the lorapt example\n");
    mosquitto_disconnect(mosq);
}

void resource_write_value(const pt_resource_opaque_t *resource, const uint8_t* value, const uint32_t value_size, void *ctx)
{
    tr_warn("Set point default value write not implemented.");
}
/*
 * Create the lwm2m structure for a "generic" sensor object. Same resources can be used
 * to represent temperature and humidity sensors by just changing the object id
 * temperature sensor id = 3303 (http://www.openmobilealliance.org/tech/profiles/lwm2m/3303.xml)
 * humidity sensor id = 3304 (http://www.openmobilealliance.org/tech/profiles/lwm2m/3304.xml)
 */
void lorapt_create_sensor_object(pt_device_t *device, uint16_t id, sensor_type_e sensor_type, const char* value, uint8_t mode)
{
    uint16_t object_id = 0;
    if (sensor_type == SENSOR_TEMPERATURE) {
        object_id = 3303;
    }
    else if (sensor_type == SENSOR_HUMIDITY) {
        object_id = 3304;
    }
    else if (sensor_type == SENSOR_GPIO) {
        object_id = 3201;
    }
    else
    {
        tr_err("error object_id");
        return;
    }

    if (device == NULL) {
        return;
    }

    // Resource value buffer ownership is transferred so we need to make copies of the const buffers passed in
    char *value_buf = strdup(value);

    if (value_buf == NULL) {
        free(value_buf);
        return;
    }

    pt_status_t status = PT_STATUS_SUCCESS;
    pt_object_t *object_sensor = pt_device_add_object(device, object_id, &status);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Object creation failed, status %d", status);
        return;
    }

    pt_object_instance_t *instance_sensor = pt_object_add_object_instance(object_sensor, 0, &status);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Object instance creation failed, status %d", status);
        // TODO: free object instance
        return;
    }

    pt_resource_opaque_t *resource_value = pt_object_instance_add_resource_with_callback(instance_sensor, id, LWM2M_OPAQUE,
                                                                                         mode, (uint8_t*)value_buf,
                                                                                         strlen(value_buf), &status , resource_write_value);

    if (status != PT_STATUS_SUCCESS) {
        tr_err("Resource creation failed, status %d", status);
        // TODO: free object and object instance
        return;
    }

    if (object_sensor == NULL || instance_sensor == NULL || resource_value == NULL) {
        // TODO: Free all structures if creating one failed
        // Free buffers
        free(value_buf);
    }
}

/*
 * Functions which translate different types of LoRa messages we receive through mqtt
 */
void lorapt_translate_gw_status_message(struct mosquitto *mosq, const char *payload, const int payload_len)
{
    json_error_t error;
    json_t *json = json_loads(payload, 0, &error);
    if (json == NULL) {
        tr_err("Could not parse node value json.");
        return;
    }
    if (lorapt_translator_started == 0) {
        lorapt_start_translator(mosq);
    }
    json_decref(json);
}

void lorapt_translate_node_joined_message(const char* payload, const int payload_len)
{
    json_error_t error;
    json_t *json = json_loads(payload, 0, &error);
    if (json == NULL) {
        tr_err("Could not parse node value json.");
        return;
    }
}

void lorapt_translate_node_capability_message(const char* deveui, const char* payload, const int payload_len)
{
    tr_info("payload: %s", payload);
    json_error_t error;

    if (lorapt_translator_started == 0) {
        tr_err("Translating capability message, PT is not registered yet.");
        return;
    }

    if (deveui == NULL || payload == NULL) {
        tr_err("Translating capability message, missing deveui or payload.");
        return;
    }

    json_t *json = json_loads(payload, 0, &error);
    if (json == NULL) {
        tr_err("Translating capability message, could not parse json.");
        return;
    }

    json_t *susiCommData = json_object_get(json, "susiCommData");
    if (!json_is_object(susiCommData)) {
        tr_err("Translating capability message, json missing susiCommData.");
        json_decref(json);
        return;
    }

    json_t *sensorInfoList = json_object_get(susiCommData, "sensorInfoList");
    json_t *infoSpec = json_object_get(susiCommData, "infoSpec");
    json_t *osInfo = json_object_get(susiCommData, "osInfo");

    if (json_is_object(sensorInfoList))
    {
        const char *sessionID = json_string_value(json_object_get(susiCommData, "sessionID"));
        if (sessionID != NULL) {
            if(session_id_exists(sessionID))
            {
                write_sensor_value(sessionID);
                write_session_t *temp_session = find_session(sessionID);
                ns_list_remove(session_list, temp_session);
                tr_info("Write sensor value done.");
            }
            else
            {
                tr_err("Translating capability message, session_id is no exists.");
                json_decref(json);
                return;               
            }
        }       
    }
    else if (json_is_object(infoSpec))
    {
        // TBD
    }
    else if (json_is_object(osInfo))
    {
        // TBD
    }
    else
    {
        fprintf(stderr, "Translating capability message, json missing sensorInfoList, infoSpec or osInfo.");
    }

    json_decref(json);
}

void lorapt_translate_node_value_message(struct mosquitto *mosq,
                                         char *deveui,
                                         const char *payload,
                                         const int payload_len)
{
    json_error_t error;
    tr_info("Translating value message");

    if (lorapt_translator_started == 0) {
        lorapt_start_translator(mosq);
        tr_err("Translating value message, PT is not registered yet.");
        return;
    }

    if (deveui == NULL || payload == NULL) {
        tr_err("Translating value message, missing deveui or payload.");
        return;
    }

    json_t *json = json_loads(payload, 0, &error);
    if (json == NULL) {
        tr_err("Translating value message, could not parse json.");
        return;
    }

    json_t *susiCommData = json_object_get(json, "susiCommData");
    if (!json_is_object(susiCommData)) {
        tr_err("Translating value message, json missing susiCommData.");
        json_decref(json);
        return;
    }

    json_t *data = json_object_get(susiCommData, "data");
    if (!json_is_object(data)) {
        tr_err("Translating value message, json missing data.");
        json_decref(json);
        return;
    }

    json_t *SenHub = json_object_get(data, "SenHub");
    if (!json_is_object(SenHub)) {
        tr_err("Translating value message, json missing SenHub.");
        json_decref(json);
        return;
    }

    json_t *SenData = json_object_get(SenHub, "SenData");
    if (!json_is_object(SenData)) {
        tr_err("Translating value message, json missing SenData.");
        json_decref(json);
        return;
    }

    json_t *ItemE = json_object_get(SenData, "e");
    if (!json_is_array(ItemE)) {
        tr_err("Translating value message, json missing ItemE.");
        json_decref(json);
        return;
    }

    // We store lwm2m representation of node values into pt_object_list_t
    // Create the device structure
    pt_status_t status = PT_STATUS_SUCCESS;
    pt_device_t *device = pt_create_device(strdup(deveui), LORAPT_DEFAULT_LIFETIME, NONE, &status);
    if (device == NULL || status != PT_STATUS_SUCCESS) {
        tr_err("Translating value message, could not create device structure");
        return;
    }
    int values_count = 0;

    // Loop through the payload array containing new values
    int ItemE_size = json_array_size(ItemE);
    for (int i = 0; i < ItemE_size; i++) {
        json_t *value_array = json_array_get(ItemE, i);
        if (!json_is_object(value_array)) {
            tr_err("Translating value message, json has invalid payload.");
            break;
        }

        const char* type = json_string_value(json_object_get(value_array, "n"));
        char value_string[8];
        // Determine type of sensor
        if (type != NULL) {
            if (strcmp(type, "Temperature") == 0 || strcmp(type, "Humidity") == 0)
            {
                double double_value = json_number_value(json_object_get(value_array, "v"));
                memset(value_string, 0, 8);
                if (strcmp(type, "Temperature") == 0) {
                    sprintf(value_string, "%2.2f", double_value);
                    lorapt_create_sensor_object(device, 5700, SENSOR_TEMPERATURE, value_string, OPERATION_READ);
                }
                else if (strcmp(type, "Humidity") == 0) {
                    sprintf(value_string, "%2.2f", double_value);
                    lorapt_create_sensor_object(device, 5700, SENSOR_HUMIDITY, value_string, OPERATION_READ);
                }
            }
            else if (strcmp(type, "GPIO1") == 0) {
                bool bool_value = json_boolean_value(json_object_get(value_array, "bv"));
                memset(value_string, 0, 8);
                sprintf(value_string, "%d", bool_value);
                lorapt_create_sensor_object(device, 5550, SENSOR_GPIO, value_string, OPERATION_READ_WRITE);
            }
            values_count++;
        }
    }

    if (values_count > 0) {
        // We need to only send values if we actually got some
        char* deveui_ctx = strdup(deveui);
        // If device has been registered, then just write the new values
        if (lorapt_device_exists(deveui)) {
            tr_info("Writing value to device %s", deveui_ctx);
            pt_write_value(g_connection, device, device->objects, lorapt_device_write_success_handler, lorapt_device_write_failure_handler, deveui_ctx);
        }
        // If device has not been registered yet, register it
        else {
            tr_info("Registering device %s", deveui_ctx);
            lorapt_add_device(device);
            pt_register_device(g_connection, device, lorapt_device_register_success_handler, lorapt_device_register_failure_handler, deveui_ctx);
        }
    }

    json_decref(json);
}

/*
 * Function for parsing the mqtt messages we receive from the LoRa gateway.
 * The event type is parsed from topic field and id's and values are parsed from payload.
 *
 * Some examples of possible topics that are received from LoRa GW:
 *
 * /cagent/admin/<devID>/agentinfoack
 * /cagent/admin/<devID>/agentactionreq
 * /cagent/admin/<devID>/deviceinfo
 */
#define LORA_TOPIC_OFFSET_COUNT 4
void lorapt_handle_message(struct mosquitto *mosq, char *topic, char *payload, int payload_len)
{
    char *saveptr;
    // Parse topic offsets to identify event and id's
    char *topic_offset[LORA_TOPIC_OFFSET_COUNT];

    if (topic == NULL) {
        return;
    }

    topic_offset[0] = strtok_r(topic, "/", &saveptr);; // points to "LoRa"
    topic_offset[1] = strtok_r(NULL, "/", &saveptr); // points to "Evt" or "{gweui}"
    topic_offset[2] = strtok_r(NULL, "/", &saveptr); // points to "Node" or "Evt"
    topic_offset[3] = strtok_r(NULL, "/", &saveptr); // points to "{deveui}"

    tr_info("lorapt handling message");
    tr_info("topic 0: %s", topic_offset[0]);
    tr_info("topic 1: %s", topic_offset[1]);
    tr_info("topic 2: %s", topic_offset[2]);
    tr_info("topic 3: %s", topic_offset[3]);

    if (strcmp(topic_offset[0], "cagent") == 0) {
        if (strcmp(topic_offset[1], "admin") == 0) {
            if (topic_offset[2] == NULL || topic_offset[3] == NULL) {
                // Topic is missing {deveui} or Cap or Val
                fprintf(stderr, "MQTT message missing deveui, Connect or Cap or Val part.");
                return;
            }
            else if (strcmp(topic_offset[3], "agentinfoack") == 0) {
                tr_info("receive agentinfoack");
                lorapt_translate_gw_status_message(mosq, payload, payload_len);
            }
            else if (strcmp(topic_offset[3], "agentactionreq") == 0) {
                tr_info("receive agentactionreq");
                lorapt_translate_node_capability_message(topic_offset[2], payload, payload_len);
            }
            else if (strcmp(topic_offset[3], "deviceinfo") == 0) {
                tr_info("receive deviceinfo");
                lorapt_translate_node_value_message(mosq, topic_offset[2], payload, payload_len);
            }
        }
    }
}

void mqtt_message_callback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message)
{
    if(message->payloadlen){
        lorapt_handle_message(mosq, message->topic, message->payload, message->payloadlen);
        printf("%s %s\n", message->topic, (char *) message->payload);
    }else{
        printf("%s (null)\n", message->topic);
    }
    fflush(stdout);
}

void mqtt_connect_callback(struct mosquitto *mosq, void *userdata, int result)
{
    if(!result){
        mosquitto_subscribe(mosq, NULL, "/cagent/admin/+/agentinfoack", 2);
        mosquitto_subscribe(mosq, NULL, "/cagent/admin/+/agentactionreq", 2);
        mosquitto_subscribe(mosq, NULL, "/cagent/admin/+/deviceinfo", 2);
    }else{
        fprintf(stderr, "Connect failed\n");
    }
}

void mqtt_subscribe_callback(struct mosquitto *mosq, void *userdata, int mid, int qos_count, const int *granted_qos)
{
    int i;

    printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
    for(i=1; i<qos_count; i++){
        printf(", %d", granted_qos[i]);
    }
    printf("\n");
}

void mqtt_log_callback(struct mosquitto *mosq, void *userdata, int level, const char *str)
{
    /* Pring all log messages regardless of level. */
    printf("%s\n", str);
}

int main(int argc, char *argv[])
{
    char *host = "localhost";
    int port = 1883;
    int keepalive = 60;
    bool clean_session = true;
    struct mosquitto *mosq = NULL;

    pt_client_initialize_trace_api();
    DocoptArgs args = docopt(argc, argv, /* help */ 1, /* version */ "0.1");
    lorapt_devices = (lorapt_device_list_t*)calloc(1, sizeof(lorapt_device_list_t));
    session_list = (write_session_list_t*)calloc(1, sizeof(write_session_t));
    ns_list_init(lorapt_devices);
    ns_list_init(session_list);

    global_pt_ctx = malloc(sizeof(protocol_translator_api_start_ctx_t));

    global_pt_ctx->hostname = NULL;
    global_pt_ctx->port = 22223;

    if (args.edge_core_host) {
        global_pt_ctx->hostname = args.edge_core_host;
    }

    if (args.edge_core_port) {
        global_pt_ctx->port = atoi(args.edge_core_port);
    }

    if (args.keep_alive) {
        keepalive = atoi(args.keep_alive);
    }
    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, clean_session, NULL);
    if(!mosq){
        fprintf(stderr, "Error: Out of memory.\n");
        return 1;
    }
    g_mosq = mosq;

    mosquitto_log_callback_set(mosq, mqtt_log_callback);
    mosquitto_connect_callback_set(mosq, mqtt_connect_callback);
    mosquitto_message_callback_set(mosq, mqtt_message_callback);
    mosquitto_subscribe_callback_set(mosq, mqtt_subscribe_callback);
    if (args.mosquitto_host) {
        host = args.mosquitto_host;
    }
    if (args.mosquitto_port) {
        port = atoi(args.mosquitto_port);
    }
    if(mosquitto_connect(mosq, host, port, keepalive)){
        fprintf(stderr, "Unable to connect.\n");
        return 1;
    }

    mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    free(global_pt_ctx);
    return 0;
}


/**
 * @}
 * close EDGE_PT_CLIENT_EXAMPLE Doxygen group definition
 */
