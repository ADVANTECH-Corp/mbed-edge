// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#ifdef TARGET_LIKE_MBED
#include "mbed.h"
#else //Linux
#include <unistd.h>
#include <sys/reboot.h>
#include <cstdlib>
#endif
#include <cerrno>
#include <string.h>
#include "edge-client/edge_client.h"
#include "edge-client/oem_role_claim.h"
#include "common/constants.h"
#include "common/pt_api_error_codes.h"
#include "update-client-common/arm_uc_config.h"
#include "update-client-common/arm_uc_types.h"
#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update-client-common/arm_uc_scheduler.h"
#include "kcm_status.h"
#include "kcm_defs.h"
#include "key_config_manager.h"
#include "fcc_defs.h"
#include "mbed-client/m2mstring.h"
#include "mbed-trace/mbed_trace.h"
#include "common_functions.h"

#include "nanostack-event-loop/eventOS_event.h"
#include "nanostack-event-loop/eventOS_event_timer.h"


#define TRACE_GROUP "oeRC"

#define OEM_ROLE_CLAIM_OBJECT_VALUE   30000

static int8_t _tasklet = -1;

namespace OemRoleClaim
{

uint32_t resource_update_bitmap = 0;

typedef enum {
    ID_SW_MANUFACTURER = 1,
    ID_SW_MODEL,
    ID_SW_DEVICE_TYPE,
    ID_VENDOR_ID,
    ID_CLASS_ID,
    ID_UPDATE_AUTH_CERT,
    ID_ENABLE_OEM_ROLE_CLAIM,
    ID_MIN_FW_VERSION_MONOTONIC_COUNTER,
    ID_APPLY_OEM_ROLE_CLAIM,
    ID_END_OF_LIST
} oem_resource_ids_e;

//typedef void(*OemRoleClaimCb)(void*);

typedef union OemRoleClaimCb {
    edge_value_updated_callback update;
    edge_execute_callback execute;
} OemRoleClaimCb_u;

typedef struct OemRoleClaimResource {
    oem_resource_ids_e resource_id;
    const char *kcm_name;
    Lwm2mResourceType resource_type;
    int resource_op;
    OemRoleClaimCb_u resource_cb;
} OemRoleClaimResource_s;


typedef struct OemRoleClaimKcm {
    oem_resource_ids_e resource_id;
    const char *kcm_name;
} OemRoleClaimKcm_s;


//internal functions
sotp_result_e sotp_data_store(const uint8_t *data, size_t data_size, sotp_type_e sotp_type);

sotp_result_e sotp_data_retreive(uint8_t *data_out, size_t data_size_max, size_t *data_actual_size_out, sotp_type_e sotp_type);

void load_kcm_param(const char *parameter, uint8_t *value, size_t *value_size);
kcm_status_e update_kcm_param(const char *parameter, const uint8_t *value, const size_t value_size);
uint32_t oem_role_claim_sotp_params_set_ex(uint32_t oem_transfer_mode, int64_t min_fw_ver_value);
uint32_t oem_role_claim_sotp_params_set();
uint32_t oem_sotp_params_reset(void);
bool is_oem_role_claim_enabled(void);
uint32_t invalidateCandidateImages(void);
void os_reboot(void);
uint32_t get_current_image_version_start();
uint32_t get_current_image_version_done(uint64_t &image_version);
uint32_t init_fw_manager();
void firmware_manager_event_handler(uint32_t event);
void set_apply_response(uint32_t response);

pt_api_result_code_e set_resource_value(oem_resource_ids_e resource_id, int32_t value);
pt_api_result_code_e set_resource_value(oem_resource_ids_e resource_id, uint8_t *value, uint32_t value_length);
bool get_resource_value(oem_resource_ids_e resource_id, uint8_t **value, uint32_t *value_length);
bool get_resource_string_as_int64(oem_resource_ids_e resource_id, int64_t *value);
bool get_resource_value_length(oem_resource_ids_e resource_id, uint32_t *value_length);

//resources callbacks
static void sw_manufacturer_value_callback(const char *object_name);
static void sw_model_number_callback(const char *object_name);
static void sw_device_type_callback(const char *object_name);
static void vendor_id_callback(const char *object_name);
static void class_id_callback(const char *object_name);
static void enable_role_claim_callback(const char *object_name);
static void min_version_callback(const char *object_name);
static void update_authentication_certificate_callback(const char *object_name);
static void apply_oem_role_claim_callback(void *arguments);

static void oem_tasklet_event_handler(arm_event_s &event);
static void apply_oem_role_claim_callback_continue_get_current_version();
static void apply_oem_role_claim_callback_continue();
static void send_internal_event(int event_type, uint32_t delay_ms);


#define RESOURCE_ID_SW_MANUFACTURER 0

OemRoleClaimResource_s oem_role_claim_resource_table[] = {
    //Obj,                                  KCM name,                                       Resource Type, Resource Operation,   Operation Callback
    {ID_SW_MANUFACTURER,                    oem_sw_manufacturer_parameter_name,             LWM2M_STRING,  OPERATION_READ_WRITE, {.update = sw_manufacturer_value_callback}},
    {ID_SW_MODEL,                           oem_sw_model_num_parameter_name,                LWM2M_STRING,  OPERATION_READ_WRITE, {.update = sw_model_number_callback}},
    {ID_SW_DEVICE_TYPE,                     oem_sw_device_type_parameter_name,              LWM2M_STRING,  OPERATION_READ_WRITE, {.update = sw_device_type_callback}},
    {ID_VENDOR_ID,                          oem_vendor_id_name,                             LWM2M_OPAQUE,  OPERATION_READ_WRITE, {.update = vendor_id_callback}},
    {ID_CLASS_ID,                           oem_class_id_name,                              LWM2M_OPAQUE,  OPERATION_READ_WRITE, {.update = class_id_callback}},
    {ID_UPDATE_AUTH_CERT,                   g_fcc_update_authentication_certificate_name,   LWM2M_OPAQUE,  OPERATION_READ_WRITE, {.update = update_authentication_certificate_callback}},
    {ID_ENABLE_OEM_ROLE_CLAIM,              oem_enable_role_claim_name,                     LWM2M_STRING,  OPERATION_READ_WRITE, {.update = enable_role_claim_callback}},
    {ID_MIN_FW_VERSION_MONOTONIC_COUNTER,   NULL,                                           LWM2M_STRING,  OPERATION_READ_WRITE, {.update = min_version_callback}},
    {ID_APPLY_OEM_ROLE_CLAIM,               NULL,                                           LWM2M_INTEGER, OPERATION_EXECUTE,    {.execute = apply_oem_role_claim_callback}},
    {ID_END_OF_LIST,                        NULL,                                           LWM2M_INTEGER, 0,                    NULL},

};


/* lookup table for printing hexadecimal values */
const uint8_t hex_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

/* Update-related */

typedef enum {
    fw_event_manager_state_ready = 0,
    fw_event_manager_state_finished = 1,
    fw_event_manager_state_error = 2
} fw_event_manager_state;

arm_uc_firmware_details_t active_firmware_details = { 0 };
fw_event_manager_state firmware_manager_event_handler_state = fw_event_manager_state_ready;


// states needed for breaking up the callback into few steps which are ran via events
typedef enum {
    STATE_CALLBACK_READY,
    STATE_GET_CURRENT_IMAGE_VERSION_STARTED,
    STATE_GET_CURRENT_IMAGE_VERSION_DONE,
    STATE_WAITING_FOR_REBOOT
} RoleClaimCallbackState;

RoleClaimCallbackState callback_state = STATE_CALLBACK_READY;

} // namespace OemRoleClaim

// event types used in communicating with the tasklet
#define OEM_TASKLET_INIT_EVENT 0
#define OEM_TASKLET_FIRMWARE_CALLBACK_EVENT 1
#define OEM_TASKLET_REBOOT_EVENT 2

// This is the time (in milliseconds) the code will let the POST response to Apply_Oem_Role_Claim
// resource to be sent until it does a reboot.
// If one wants the response resends to function at least once, the delay should be longer than
// MBED_CLIENT_RECONNECTION_INTERVAL (which is 5s by default).
#define OEM_TASKLET_REBOOT_DELAY 5500

pt_api_result_code_e OemRoleClaim::set_resource_value(oem_resource_ids_e resource_id, uint8_t *value, uint32_t value_length)
{
    // edgeclient_set_resource_value() function is combined with creation so it has arguments for resource_type also.
    // resource_type information is only available in the oem_role_claim_resource_table and the resource_id is not
    // the same as the the index in the table (resource_id is larger by one)
    OemRoleClaim::OemRoleClaimResource_s *resource = NULL;
    OemRoleClaim::OemRoleClaimResource_s *resource_items_iter = &oem_role_claim_resource_table[0];
    for (; resource_items_iter->resource_id != ID_END_OF_LIST; resource_items_iter++) {
        if (resource_items_iter->resource_id == resource_id) {
            resource = resource_items_iter;
            break;
        }
    }

    if (resource == NULL) {
        // Given resource_id was not found, fail the set resource.
        return PT_API_RESOURCE_NOT_FOUND;
    }

    return edgeclient_set_resource_value(
               NULL,
               OEM_ROLE_CLAIM_OBJECT_VALUE,
               0,
               resource_id,
               value,
               value_length,
               resource->resource_type,
               resource->resource_op,
               NULL);
}

pt_api_result_code_e OemRoleClaim::set_resource_value(oem_resource_ids_e resource_id, int32_t value)
{
    uint8_t value_buf[4];

    // Convert value to network byte order
    common_write_32_bit((uint32_t)value, value_buf);

    return set_resource_value(resource_id, value_buf, (uint32_t)sizeof(value_buf));
}

bool OemRoleClaim::get_resource_value(oem_resource_ids_e resource_id, uint8_t **value, uint32_t *value_length)
{
    return edgeclient_get_resource_value(
               NULL,
               OEM_ROLE_CLAIM_OBJECT_VALUE,
               0,
               resource_id,
               value,
               value_length);
}

bool OemRoleClaim::get_resource_string_as_int64(oem_resource_ids_e resource_id, int64_t *value)
{
    // Read resource value
    uint8_t *value_buf = NULL; // get_value() will try to free this pointer.
    uint32_t value_len;

    bool retval = get_resource_value(resource_id, &value_buf, &value_len);
    if (retval == false) {
        return false;
    }

    // Convert resource string to int64_t
    char *endptr;
    int64_t value_int64;

    errno = 0;
    value_int64 = strtoll((const char *)value_buf, &endptr, 10);
    free(value_buf);

    if ((errno == ERANGE && (value_int64 == LLONG_MAX || value_int64 == LLONG_MIN)) || (errno != 0 && value_int64 == 0)) {
        int errsv = errno;
        tr_error("strtoull() failed with %d", errsv);
        return false;
    }

    if ((uint8_t *)endptr == value_buf) {
        tr_error("strtoull() could not find any digits");
        return false;
    }

    if (*endptr != '\0') {
        tr_error("strtoull() trailing characters after number");
        return false;
    }

    *value = value_int64;
    return true;
}

bool OemRoleClaim::get_resource_value_length(oem_resource_ids_e resource_id, uint32_t *value_length)
{
    uint8_t *value_buf = NULL; // get_value() will try to free this pointer.
    bool retval = get_resource_value(resource_id, &value_buf, value_length);
    if (retval == true) {
        free(value_buf); // Free dummy buffer on succesful read
    }
    return retval;
}


void OemRoleClaim::firmware_manager_event_handler(uint32_t event)
{
    tr_debug("firmware_manager_event_handler received and thread id is :%p", (void *)pal_osThreadGetId());
    switch (event) {
        case UCFM_EVENT_INITIALIZE_DONE:
            tr_debug("UCFM_EVENT_INITIALIZE_DONE");
            // XXX: is this used/needed?! if so, then add the event passing here too
            break;

        case UCFM_EVENT_PREPARE_DONE:
            tr_debug("UCFM_EVENT_PREPARE_DONE");
            break;

        case UCFM_EVENT_WRITE_DONE:
            break;

        case UCFM_EVENT_FINALIZE_DONE:
            tr_debug("UCFM_EVENT_FINALIZE_DONE");
            break;

        case UCFM_EVENT_GET_FIRMWARE_DETAILS_DONE:
            tr_debug("UCFM_EVENT_GET_FIRMWARE_DETAILS_DONE");
            break;

        case UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE:
            tr_debug("UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE");
            tr_debug("Active Firmware version: %" PRIu64, active_firmware_details.version);
            firmware_manager_event_handler_state = fw_event_manager_state_finished;
            send_internal_event(OEM_TASKLET_FIRMWARE_CALLBACK_EVENT, 0);
            break;

        case ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_ERROR:
            tr_error("Active firmware details event handler called with failure event");
            firmware_manager_event_handler_state = fw_event_manager_state_error;
            send_internal_event(OEM_TASKLET_FIRMWARE_CALLBACK_EVENT, 0);
            break;

        default:
            tr_error("Unexpected event: %" PRIu32, event);
            firmware_manager_event_handler_state = fw_event_manager_state_error;
            break;
    }
}

uint32_t OemRoleClaim::init_fw_manager()
{
    firmware_manager_event_handler_state = fw_event_manager_state_ready;

    arm_uc_error_t error;

    error = ARM_UC_FirmwareManager.Initialize(firmware_manager_event_handler);

    if (error.error != ERR_NONE) {
        tr_error("Unable to initialize update firmware manager, error: %d", error.error);
        //Send negative response to POST operation
        return MBED_ORC_INIT_FW_MANAGER_ERROR;
    }

    return MBED_ORC_SUCCESS;
}


uint32_t OemRoleClaim::invalidateCandidateImages()
{
    //not essential in Linux
    return MBED_ORC_SUCCESS;
}

void OemRoleClaim::os_reboot(void)
{
#ifdef TARGET_LIKE_MBED
    NVIC_SystemReset();
#else
    sync(); //writes any data buffered in memory out to disk
    reboot(RB_AUTOBOOT);
#endif
}


/*
    getCurrentImageVersion()
        parameter
        return values
             MBED_ORC_SUCCESS:                              Success
             MBED_ORC_GET_ACTIVE_FW_DETAILS_UNKNOWN_ERROR:  Information Not Ready
             MBED_ORC_GET_ACTIVE_FW_DETAILS_ERROR:          Failed to get version information
*/
uint32_t OemRoleClaim::get_current_image_version_start()
{
    arm_uc_error_t error;

    // Start a asynchronous operation for querying the active firmware version. Completition happens
    // upon call of firmware_manager_event_handler()
    // Note: this may fail either immediately or via callback.

    error = ARM_UC_FirmwareManager.GetActiveFirmwareDetails(&active_firmware_details);

    if (error.error != ERR_NONE) {
        tr_error("Unable to get active firmware details, error: %d", error.error);
        return MBED_ORC_GET_ACTIVE_FW_DETAILS_ERROR;
    } else {

        //Wait for the signal from firmware manager event handler

        tr_debug("firmware_manager_event_handler_state = %d", firmware_manager_event_handler_state);

    }

}

// Next step of get_current_image_version_start(), which converts the status code and fetches the
// actual result version number to user provided value. This may be called after one has received the
// firmware_manager_event_handler() callback.
uint32_t OemRoleClaim::get_current_image_version_done(uint64_t &image_version)
{
    tr_debug("get_current_image_version_done, state: %d", firmware_manager_event_handler_state);

    if (firmware_manager_event_handler_state == fw_event_manager_state_finished) {
        image_version = active_firmware_details.version;
        return MBED_ORC_SUCCESS;
    } else if (firmware_manager_event_handler_state == fw_event_manager_state_ready) {
        return MBED_ORC_GET_ACTIVE_FW_DETAILS_UNKNOWN_ERROR; // FirmwareManager Initialization and GetActiveFirmwareDetails() not completed yet
    } else {
        return MBED_ORC_GET_ACTIVE_FW_DETAILS_ERROR; // Some errors in the event handler
    }

    return MBED_ORC_SUCCESS;
}

sotp_result_e OemRoleClaim::sotp_data_store(const uint8_t *data, size_t data_size, sotp_type_e sotp_type)
{
    sotp_result_e sotp_result;
    uint16_t required_size = 0;
    int64_t aligned_8_bytes_buffer[1];

    if ((sotp_type != SOTP_TYPE_MIN_FW_VERSION) && (sotp_type != SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED)) {
        return SOTP_NOT_FOUND;
    }

    if (sotp_type == SOTP_TYPE_MIN_FW_VERSION) {
        required_size = sizeof(uint64_t);
    } else if (sotp_type == SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED) {
        required_size = sizeof(uint32_t);
    }

    if (data_size != required_size) {
        return SOTP_WRITE_ERROR;
    }

    memcpy(aligned_8_bytes_buffer, data, data_size);

    sotp_result = sotp_set(sotp_type, (uint16_t)(data_size), (const uint32_t *)aligned_8_bytes_buffer);

    return sotp_result;

}


sotp_result_e OemRoleClaim::sotp_data_retreive(uint8_t *data_out, size_t data_size_max, size_t *data_actual_size_out, sotp_type_e sotp_type)
{
    sotp_result_e sotp_result;
    uint16_t required_size = 0;
    int64_t aligned_8_bytes_buffer[1] = { 0 };
    uint16_t actual_data_size = 0;

    if ((sotp_type != SOTP_TYPE_MIN_FW_VERSION) && (sotp_type != SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED)) {
        return SOTP_NOT_FOUND;
    }

    if (sotp_type == SOTP_TYPE_MIN_FW_VERSION) {
        required_size = sizeof(uint64_t);
    } else if (sotp_type == SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED) {
        required_size = sizeof(uint32_t);
    }

    if (data_size_max < required_size) {
        return SOTP_READ_ERROR;
    }

    // Retrieve buf from SOTP. Cast is OK since size must be multiple of 8
    sotp_result = sotp_get(sotp_type, (uint16_t)data_size_max, (uint32_t *)aligned_8_bytes_buffer, &actual_data_size);
    if (sotp_result != SOTP_SUCCESS) {
        return sotp_result;
    }

    // Copy from aligned buffer to callers uint8_t* buffer
    memcpy(data_out, aligned_8_bytes_buffer, actual_data_size);

    *data_actual_size_out = (size_t)(actual_data_size);

    return SOTP_SUCCESS;

}



void OemRoleClaim::load_kcm_param(const char *parameter, uint8_t *value, size_t *value_size)
{

    kcm_status_e kcm_status;

    //load kcm values
    if (strcmp(parameter, g_fcc_update_authentication_certificate_name)) { //load config param

        // Get parameter value to buffer
        kcm_status = kcm_item_get_data((const uint8_t *)parameter,
                                       strlen(parameter),
                                       KCM_CONFIG_ITEM,
                                       value,
                                       CONFIG_PARAMS_BUFFER_SIZE,
                                       value_size);

        if (kcm_status != KCM_STATUS_SUCCESS) {
            tr_error("config parameter [%s] kcm get error %d", parameter, kcm_status);
            *value_size = 0;
        }

    } else { // load certificate

        kcm_status = kcm_item_get_data((const uint8_t *)parameter,
                                       strlen(parameter),
                                       KCM_CERTIFICATE_ITEM,
                                       value,
                                       CERTIFICATE_BUFFER_SIZE,
                                       value_size);

        if (kcm_status != KCM_STATUS_SUCCESS) {
            tr_error("certificate [%s] kcm get error %d", parameter, kcm_status);
            *value_size = 0;
        }

    }

}


kcm_status_e OemRoleClaim::update_kcm_param(const char *parameter, const uint8_t *value, const size_t value_size)
{
    kcm_status_e kcm_status;

    if (strcmp(parameter, g_fcc_update_authentication_certificate_name)) { //update config param

        tr_debug("deleting %s", parameter);
        kcm_item_delete((const uint8_t *)parameter,
                        strlen(parameter),
                        KCM_CONFIG_ITEM);



        //Set parameter to storage
        kcm_status = kcm_item_store((const uint8_t *)parameter,
                                    strlen(parameter),
                                    KCM_CONFIG_ITEM,
                                    false,
                                    value,
                                    value_size,
                                    NULL);

    } else {    //certificate

        tr_debug("deleting mbed.UpdateAuthCert");
        kcm_item_delete((const uint8_t *)parameter,
                        strlen(parameter),
                        KCM_CERTIFICATE_ITEM);

        //Set parameter to storage
        kcm_status = kcm_item_store((const uint8_t *)parameter,
                                    strlen(parameter),
                                    KCM_CERTIFICATE_ITEM,
                                    false,
                                    value,
                                    value_size,
                                    NULL);
    }

    return kcm_status;
}


void OemRoleClaim::sw_manufacturer_value_callback(const char *object_name)
{
    (void) object_name;
    tr_debug("Updating SW Manufacturer");

    //clear relevant bit in the bitmap
    resource_update_bitmap &= ~SW_MANUFACTURER_BIT;

    //read resource length
    uint32_t value_length;
    bool retval = get_resource_value_length(OemRoleClaim::ID_SW_MANUFACTURER, &value_length);
    if (retval == false) {
        tr_error("SW Manufacturer length retrieval failed");
        return;
    }

    //check value size
    if (value_length > (CONFIG_PARAMS_BUFFER_SIZE - 1)) {
        tr_error("SW Manufacturer value length %" PRIu32 " exceeds max length %" PRIu32 ", not updating bitmask",
                 value_length, CONFIG_PARAMS_BUFFER_SIZE - 1);
        return;
    }

    //set relevant bit in the bitmap
    resource_update_bitmap |= SW_MANUFACTURER_BIT;
}

void OemRoleClaim::sw_model_number_callback(const char *object_name)
{
    (void) object_name;
    tr_debug("Updating SW Model Number");

    //clear relevant bit in the bitmap
    resource_update_bitmap &= ~SW_MODEL_NUMBER_BIT;

    //read resource length
    uint32_t value_length;
    bool retval = get_resource_value_length(OemRoleClaim::ID_SW_MODEL, &value_length);
    if (retval == false) {
        tr_error("SW Model Number length retrieval failed");
        return;
    }

    //check value size
    if (value_length > (CONFIG_PARAMS_BUFFER_SIZE - 1)) {
        tr_error("SW Model Number value length %" PRIu32 " exceeds max length %" PRIu32 ", not updating bitmask",
                 value_length, CONFIG_PARAMS_BUFFER_SIZE - 1);
        return;
    }

    //set relevant bit in the bitmap
    resource_update_bitmap |= SW_MODEL_NUMBER_BIT;
}


void OemRoleClaim::sw_device_type_callback(const char *object_name)
{
    (void) object_name;
    tr_debug("Updating SW Device Type value");

    //clear relevant bit in the bitmap
    resource_update_bitmap &= ~SW_DEVICE_TYPE_BIT;

    //read resource length
    uint32_t value_length;
    bool retval = get_resource_value_length(OemRoleClaim::ID_SW_DEVICE_TYPE, &value_length);
    if (retval == false) {
        tr_error("SW Device Type length retrieval failed");
        return;
    }

    //check value size
    if (value_length > (CONFIG_PARAMS_BUFFER_SIZE - 1)) {
        tr_error("SW Device Type value length %" PRIu32 " exceeds max length %" PRIu32 ", not updating bitmask",
                 value_length, CONFIG_PARAMS_BUFFER_SIZE - 1);
        return;
    }

    //set relevant bit in the bitmap
    resource_update_bitmap |= SW_DEVICE_TYPE_BIT;
}


void OemRoleClaim::vendor_id_callback(const char *object_name)
{
    (void) object_name;
    tr_debug("Updating Vendor ID");

    //clear relevant bit in the bitmap
    resource_update_bitmap &= ~VENDOR_ID_BIT;

    //read resource length
    uint32_t value_length;
    bool retval = get_resource_value_length(OemRoleClaim::ID_VENDOR_ID, &value_length);
    if (retval == false) {
        tr_error("Failed to get Vendor ID resource value length, not updating bitmask");
        return;
    }

    //check value size
    if (value_length != UUID5_SIZE_IN_BYTES) {
        tr_error("Incorrect Vendor ID resource value length %" PRIu32 ", expected: %" PRIu32 ", not updating bitmask",
                 value_length, UUID5_SIZE_IN_BYTES);
        return;
    }

    //set relevant bit in the bitmap
    resource_update_bitmap |= VENDOR_ID_BIT;
}


void OemRoleClaim::class_id_callback(const char *object_name)
{
    (void) object_name;
    tr_debug("Updating Class ID");

    //clear relevant bit in the bitmap
    resource_update_bitmap &= ~CLASS_ID_BIT;

    //read resource length
    uint32_t value_length;
    bool retval = get_resource_value_length(OemRoleClaim::ID_CLASS_ID, &value_length);
    if (retval == false) {
        tr_error("Failed to get Class ID resource value length, not updating bitmask");
        return;
    }

    //check value size
    if (value_length != UUID5_SIZE_IN_BYTES) {
        tr_error("Incorrect Class ID resource value length %" PRIu32 ", expected: %" PRIu32 ", not updating bitmask",
                 value_length, UUID5_SIZE_IN_BYTES);
        return;
    }

    //set relevant bit in the bitmap
    resource_update_bitmap |= CLASS_ID_BIT;
}


void OemRoleClaim::min_version_callback(const char *object_name)
{
    (void) object_name;
    tr_debug("Updating Minimum FW Version Monotonic Counter");

    //clear relevant bit in the bitmap
    resource_update_bitmap &= ~MIN_FW_VERSION_MONOTONIC_COUNTER_BIT;

    // Validating we are dealing with a string that represents a number
    int64_t resource_val = 0;
    bool retval = OemRoleClaim::get_resource_string_as_int64(ID_MIN_FW_VERSION_MONOTONIC_COUNTER, &resource_val);
    if (retval == false || resource_val < 0) {
        tr_error("Value of 'Min FW version monotonic counter' doesn't correctly represent a positive int64 number");
        return;
    }

    tr_debug("min version value: %" PRId64, resource_val);

    //set relevant bit in the bitmap
    resource_update_bitmap |= MIN_FW_VERSION_MONOTONIC_COUNTER_BIT;
}

void OemRoleClaim::update_authentication_certificate_callback(const char *object_name)
{
    (void) object_name;
    tr_debug("Updating Update Authentication certificate");

    //clear relevant bit in the bitmap
    resource_update_bitmap &= ~UPDATE_AUTH_CERT_BIT;

    //read resource length
    uint32_t value_length;
    bool retval = get_resource_value_length(OemRoleClaim::ID_UPDATE_AUTH_CERT, &value_length);
    if (retval == false) {
        tr_error("Update Authentication certificate length retrieval failed");
        return;
    }

    //check value size
    if (value_length > (CERTIFICATE_BUFFER_SIZE - 1)) {
        tr_error("Update Authentication certificate value length %" PRIu32 " exceeds max length %" PRIu32 ", not updating bitmask",
                 value_length, CERTIFICATE_BUFFER_SIZE - 1);
        return;
    }

    //set relevant bit in the bitmap
    resource_update_bitmap |= UPDATE_AUTH_CERT_BIT;

    tr_debug("Updating auth certificate");
}


void OemRoleClaim::enable_role_claim_callback(const char *object_name)
{
    (void) object_name;
    char value;
    uint32_t value_length;

    tr_debug("Updating enable role claim flag");

    bool retval;
    uint8_t *value_buf = NULL; // get_value() will try to free this pointer
    retval = get_resource_value(ID_ENABLE_OEM_ROLE_CLAIM, &value_buf, &value_length);
    if (retval == false) {
        tr_error("failed to read role_claim_callback resource, not updating bitmask");
        //clear relevant bit in the bitmap
        resource_update_bitmap &= ~ENABLE_OEM_ROLE_CLAIM_BIT;
        return;
    }

    value = *(char *)value_buf;
    free(value_buf);

    if (((value != '0') && (value != '1')) || (value_length != sizeof(uint8_t))) {
        tr_error("Unsupported value for enable role_claim_callback: %c, not updating bitmask", value);
        //clear relevant bit in the bitmap
        resource_update_bitmap &= ~ENABLE_OEM_ROLE_CLAIM_BIT;
        return;
    }

    tr_debug("Value is: %c", value);

    //set relevant bit in the bitmap
    resource_update_bitmap |= ENABLE_OEM_ROLE_CLAIM_BIT;
}

void OemRoleClaim::set_apply_response(uint32_t response)
{
    // Set the apply resource value to the return code
    set_resource_value(ID_APPLY_OEM_ROLE_CLAIM, response);
    // Send delayed response with the resource value in the payload
    edgeclient_send_delayed_response(NULL, OEM_ROLE_CLAIM_OBJECT_VALUE, 0, ID_APPLY_OEM_ROLE_CLAIM);
}


// Send a event to the tasklet. Processing happens on the event loop thread which calls
// oem_tasklet_event_handler_wrapper().
void OemRoleClaim::send_internal_event(int event_type, uint32_t delay_ms)
{
    arm_event_t event;

    memset(&event, 0, sizeof(event));

    event.event_type = event_type;
    event.receiver = _tasklet;
    event.sender =  _tasklet;
    event.priority = ARM_LIB_MED_PRIORITY_EVENT;

    if (eventOS_event_send_after(&event, eventOS_event_timer_ms_to_ticks(delay_ms)) == NULL) {
        assert(false);
    }
}

// The event API needs a event handler with C calling convention, which is here merely
// a wrapper that calls the C++ side.
extern "C" {

    static void oem_tasklet_event_handler_wrapper(arm_event_s *event)
    {
        assert(event);
        // if there was a instance of the OemRoleClaim -object, its pointer on event.data_ptr
        // could be dereferenced here, but no need as this class is just a flat collection
        // of static variables.
        OemRoleClaim::oem_tasklet_event_handler(*event);
    }

}

void OemRoleClaim::oem_tasklet_event_handler(arm_event_s &event)
{
    tr_debug("OemRoleClaim::oem_tasklet_event_handler: %d", event.event_type);

    switch (event.event_type) {
        case OEM_TASKLET_INIT_EVENT:
            tr_debug("OEM_TASKLET_INIT_EVENT - tasklet initialized");
            break;
        case OEM_TASKLET_FIRMWARE_CALLBACK_EVENT:
            tr_debug("OEM_TASKLET_FIRMWARE_CALLBACK_EVENT");
            if (callback_state == STATE_GET_CURRENT_IMAGE_VERSION_STARTED) {
                apply_oem_role_claim_callback_continue_get_current_version();
            } else if (callback_state == STATE_GET_CURRENT_IMAGE_VERSION_DONE) {
                // there should not be more than one response for a version query
                assert(false);
            } else {
                assert(false);
            }
            break;

        case OEM_TASKLET_REBOOT_EVENT:
            tr_debug("OEM_TASKLET_REBOOT_EVENT");
            os_reboot();
            break;

        default:
            assert(false);
    }
}

void OemRoleClaim::apply_oem_role_claim_callback(void *arguments)
{
    (void) arguments;
    //max buffer for config params and sotp values
    uint8_t params_value_buf_1[CONFIG_PARAMS_BUFFER_SIZE];
    uint8_t params_value_buf_2[CONFIG_PARAMS_BUFFER_SIZE];
    size_t params_value_size_1 = 0;
    size_t params_value_size_2 = 0;
    uint32_t status = MBED_ORC_SUCCESS;

    tr_debug("OemRoleClaim::apply_oem_role_claim_callback()..");

    //check if Oem Role Claim enabled in KCM
    if (is_oem_role_claim_enabled() == false) {
        tr_error("Oem Role Claim Disabled - access forbidded! Returning: %u", MBED_ORC_FEATURE_DISABLED);
        set_apply_response(MBED_ORC_FEATURE_DISABLED);
        return;
    }

    //check if there are missing values in the Oem Role Claim object
    if ((resource_update_bitmap & ALL_RESOURCES_UPDATED_MASK) != ALL_RESOURCES_UPDATED_MASK) {
        tr_error("Oem Role Claim resources weren't updated - failed to claim OEM Role! Returning: %u, bitmask: 0x%08" PRIX32,
                 MBED_ORC_SOME_RESOURCES_NOT_YET_UPDATED, resource_update_bitmap);
        set_apply_response(MBED_ORC_SOME_RESOURCES_NOT_YET_UPDATED);
        return;
    }

    //reset the bitmap
    resource_update_bitmap = 0;

    /*
    Check that:
    SW Manufacturer  (ORC object resource) != advantech.SwManufacturer (in KCM)
    or,
    Sw Model Number (ORC object resource) != advantech.SwModelNumber  (in KCM)
    */

    //load sw manufacturer
    load_kcm_param(oem_sw_manufacturer_parameter_name, params_value_buf_1, &params_value_size_1);
    if (params_value_size_1 == 0) {
        tr_error("Failed loading %s from KCM, Oem Role not claimed. Returning: %d",
                 oem_sw_manufacturer_parameter_name, MBED_ORC_FAILED_GETTING_SW_MANUFACTURER_FROM_KCM);
        set_apply_response(MBED_ORC_FAILED_GETTING_SW_MANUFACTURER_FROM_KCM);
        return;
    }

    // Null terminating the string
    params_value_buf_1[MIN_LENGTH(params_value_size_1, CONFIG_PARAMS_BUFFER_SIZE - 1)] = '\0';

    //load sw model number
    load_kcm_param(oem_sw_model_num_parameter_name, params_value_buf_2, &params_value_size_2);
    if (params_value_size_2 == 0) {
        tr_error("Failed loading %s from KCM, Oem Role not claimed. Returning: %d",
                 oem_sw_model_num_parameter_name, MBED_ORC_FAILED_GETTING_SW_MODEL_NUMBER_FROM_KCM);
        set_apply_response(MBED_ORC_FAILED_GETTING_SW_MODEL_NUMBER_FROM_KCM);
        return;
    }

    // Null terminating the string
    params_value_buf_2[MIN_LENGTH(params_value_size_2, CONFIG_PARAMS_BUFFER_SIZE - 1)] = '\0';

    //compare sw manufacturer and model
    bool retval;

    uint8_t *sw_manufacturer_buf = NULL; // get_value() will try to free this pointer.
    uint32_t sw_manufacturer_len;
    uint8_t *sw_model_buf = NULL; // get_value() will try to free this pointer.
    uint32_t sw_model_len;

    retval = get_resource_value(ID_SW_MANUFACTURER, &sw_manufacturer_buf, &sw_manufacturer_len);
    if (retval == false) {
        printf("failed to get ID_SW_MANUFACTURER resource value");
        assert(0); //TODO set_apply_response() with proper value
    }

    retval = get_resource_value(ID_SW_MODEL, &sw_model_buf, &sw_model_len);
    if (retval == false) {
        free(sw_manufacturer_buf);
        printf("failed to get ID_SW_MODEL resource value");
        assert(0); //TODO set_apply_response() with proper value
    }

    tr_debug("SW Manufacturer - KCM: %s, resource: %s", params_value_buf_1, sw_manufacturer_buf);
    tr_debug("SW Model Number - KCM: %s, resource: %s", params_value_buf_2, sw_model_buf);

    bool sw_manufacturer_match_length = sw_manufacturer_len == params_value_size_1;
    bool sw_manufacturer_match_content = memcmp(params_value_buf_1, sw_manufacturer_buf, params_value_size_1) == 0;
    bool sw_model_match_length = sw_model_len == params_value_size_2;
    bool sw_model_match_content = memcmp(params_value_buf_2, sw_model_buf, params_value_size_2) == 0;

    free(sw_manufacturer_buf);
    free(sw_model_buf);

    if (sw_manufacturer_match_length && \
            sw_manufacturer_match_content && \
            sw_model_match_length && \
            sw_model_match_content) {

        tr_error("SW manufacturer and SW model number were not changed, Role claim was not activated. Returning: %u",
                 MBED_ORC_SW_MANUFACTURER_AND_SW_MODEL_NUMBER_UNCHANGED);
        set_apply_response(MBED_ORC_SW_MANUFACTURER_AND_SW_MODEL_NUMBER_UNCHANGED);
        return;
    }

    //*********************Role Claim********************************//

    tr_debug("OEM Role claim flow initiated");

    //init fw manager
    status = init_fw_manager();
    if (status != MBED_ORC_SUCCESS) {
        tr_error("Failed init_fw_manager, returning: %" PRIu32, status);
        set_apply_response(status);
        return;
    }

    //Delete all candidate images
    status = invalidateCandidateImages();
    if (status != MBED_ORC_SUCCESS) {
        tr_error("Failed invalidateCandidateImages, returning: %" PRIu32, status);
        set_apply_response(status);
        return;
    }

    //compare advantech.SwManufacturer and  mbed.Manufacturer
    load_kcm_param(g_fcc_manufacturer_parameter_name, params_value_buf_2, &params_value_size_2);
    if (params_value_size_2 == 0) {
        tr_error("Failed loading %s from KCM, returning: %d",
                 g_fcc_manufacturer_parameter_name, MBED_ORC_FAILED_GETTING_MBED_MANUFACTURER_FROM_KCM);
        set_apply_response(MBED_ORC_FAILED_GETTING_MBED_MANUFACTURER_FROM_KCM);
        return;
    }

    // Preserving Manufacturer image version
    // ========================================================================

    // Checking if SwManufacturer == mbed.Manufacturer
    if ((params_value_size_1 == params_value_size_2) &&
            (memcmp(params_value_buf_1, params_value_buf_2, params_value_size_1) == 0)) {

        tr_debug("apply_oem_role_claim_callback - starting async get_current_image_version..");

        // this is a asynchronous operation, which needs to be handled in via event mechanism
        status = get_current_image_version_start();

        if (status != MBED_ORC_SUCCESS) {
            tr_error("Failed get_current_image_version, returning %" PRIu32, status);
            set_apply_response(status);
            return;
        }

        tr_debug("apply_oem_role_claim_callback - async get_current_image_version started, waiting for event");

        callback_state = STATE_GET_CURRENT_IMAGE_VERSION_STARTED;

        // the next step is in apply_oem_role_claim_callback_continue_get_current_version(),
        // which is called when the operation started by get_current_image_version_start() completes.

    } else {

        // this is done for integrity check reasons only
        callback_state = STATE_GET_CURRENT_IMAGE_VERSION_DONE;

        // continue on next step immediately, as there were no need to do a async version query
        apply_oem_role_claim_callback_continue();
    }

    tr_debug("OemRoleClaim::apply_oem_role_claim_callback()..done");
}

// The next phase of apply_oem_role_claim_callback(), which is called either from event handler
// when the get_current_image_version_start() completes.
void OemRoleClaim::apply_oem_role_claim_callback_continue_get_current_version()
{
    tr_debug("apply_oem_role_claim_callback_continue_get_current_version()");

    assert(callback_state == STATE_GET_CURRENT_IMAGE_VERSION_STARTED);

    uint64_t image_version;
    kcm_status_e kcm_status;
    uint32_t status;

    // now the async GetActiveFirmwareDetails() has completed (with success or error), so let's
    // query the status and result.
    status = get_current_image_version_done(image_version);
    if (status != MBED_ORC_SUCCESS) {
        tr_error("Failed get_current_image_version, returning %" PRIu32, status);
        set_apply_response(status);
        return;
    }

    //set advantech.MinimumOemFwVersionMonotonicCounter to current software version counter
    kcm_status = update_kcm_param(oem_min_fw_ver_monotonic_counter, (uint8_t *)image_version, sizeof(uint64_t));
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed updating KCM value: %s, status: %u, returning: %u",
                 oem_min_fw_ver_monotonic_counter, kcm_status, MBED_ORC_FAILED_SETTING_MIN_OEM_FW_VERSION_TO_KCM);
        set_apply_response(MBED_ORC_FAILED_SETTING_MIN_OEM_FW_VERSION_TO_KCM);
        return;
    }

    callback_state = STATE_GET_CURRENT_IMAGE_VERSION_DONE;

    apply_oem_role_claim_callback_continue();
}

// next step of apply_oem_role_claim_callback()
void OemRoleClaim::apply_oem_role_claim_callback_continue()
{
    tr_debug("apply_oem_role_claim_callback_continue()");

    assert(callback_state == STATE_GET_CURRENT_IMAGE_VERSION_DONE);

    uint32_t status = MBED_ORC_SUCCESS;
    kcm_status_e kcm_status;
    bool retval;

    const OemRoleClaimKcm_s oem_role_claim_kcm_table[] = {

        { ID_SW_MANUFACTURER,         oem_sw_manufacturer_parameter_name                          },
        { ID_SW_MODEL,                oem_sw_model_num_parameter_name                             },
        { ID_SW_DEVICE_TYPE,          oem_sw_device_type_parameter_name                           },
        { ID_VENDOR_ID,               oem_vendor_id_name,                                         },
        { ID_CLASS_ID,                oem_class_id_name,                                          },
        { ID_UPDATE_AUTH_CERT,        g_fcc_update_authentication_certificate_name      },
        { ID_ENABLE_OEM_ROLE_CLAIM,   oem_enable_role_claim_name                                  },
        { ID_END_OF_LIST,                NULL,                                                    },

    };
    // Write Oem Claim Resources into KCM and SOTP
    // ========================================================================

    // Write Oem Claim Resources into KCM

    const OemRoleClaimKcm_s *kcm_items_iter = &oem_role_claim_kcm_table[0];
    for (; kcm_items_iter->resource_id != ID_END_OF_LIST; kcm_items_iter++) {
        uint32_t value_len;
        uint8_t *value_buf = NULL; // get_value() will try to free this pointer.

        retval = get_resource_value(kcm_items_iter->resource_id, &value_buf, &value_len);

        if (retval == false) {
            tr_error("Failed updating KCM value: %s, status: %d, returning: %u",
                     kcm_items_iter->kcm_name, kcm_status, MBED_ORC_FAILED_SETTING_VALUE_TO_KCM);
            assert(0); //TODO call proper set_apply_response()
            return;
        }

        kcm_status = update_kcm_param(kcm_items_iter->kcm_name, value_buf, (size_t)value_len);
        free(value_buf);
        if (kcm_status != KCM_STATUS_SUCCESS) {
            tr_error("Failed updating KCM value: %s, status: %d, returning: %u",
                     kcm_items_iter->kcm_name, kcm_status, MBED_ORC_FAILED_SETTING_VALUE_TO_KCM);
            set_apply_response(MBED_ORC_FAILED_SETTING_VALUE_TO_KCM);
            return;
        }
    }

    //write parameters into sotp
    status = oem_role_claim_sotp_params_set();
    if (status != MBED_ORC_SUCCESS) {
        tr_error("Failed updating SOTP parameters, returning: %" PRIu32, status);
        set_apply_response(status);
        return;
    }


    //set advantech.OemTransferred in KCM
    uint32_t oem_transfer_flag = true;
    kcm_status = update_kcm_param(oem_transferred_name, (uint8_t *)&oem_transfer_flag, sizeof(uint32_t));
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed updating KCM value: %s, status: %d, returning: %u",
                 oem_transferred_name, kcm_status, MBED_ORC_FAILED_SETTING_OEM_TRANSFER_FLAG_TO_KCM);
        set_apply_response(MBED_ORC_FAILED_SETTING_OEM_TRANSFER_FLAG_TO_KCM);
        return;
    }

    tr_debug("OEM Role claim flow completed successfully!");
    set_apply_response(MBED_ORC_SUCCESS);

    // The reboot can not happen immediately, as the response needs to be sent. The response
    // sending API is synchronous, but the data may be actually sent by the networking stack
    // after "some" time via multiple events. The reponse is confirmable, but there is currently
    // no way to know when the confirmation to it is received.
    // Hence this delay.
    tr_debug("Rebooting after %d ms...", OEM_TASKLET_REBOOT_DELAY);

    callback_state = STATE_WAITING_FOR_REBOOT;

    send_internal_event(OEM_TASKLET_REBOOT_EVENT, OEM_TASKLET_REBOOT_DELAY);
}


uint32_t OemRoleClaim::oem_sotp_params_reset()
{
    //reset Minimum OEM transfer mode flag
    const uint32_t oem_transfer_mode = (uint32_t)false;
    //reset Minimum FW Version Monotonic Counter
    const int64_t min_fw_version = 0;

    return oem_role_claim_sotp_params_set_ex(oem_transfer_mode, min_fw_version);
}

uint32_t OemRoleClaim::oem_role_claim_sotp_params_set()
{
    const uint32_t oem_transfer_mode = (uint32_t)true;
    int64_t min_fw_version;
    bool retval = OemRoleClaim::get_resource_string_as_int64(ID_MIN_FW_VERSION_MONOTONIC_COUNTER, &min_fw_version);
    if (retval == false) {
        tr_error("Failed to get min_fw_version resource");
        return MBED_ORC_FAILED_SETTING_MIN_FW_VERSION_TO_SOTP;
    }

    return oem_role_claim_sotp_params_set_ex(oem_transfer_mode, min_fw_version);
}

uint32_t OemRoleClaim::oem_role_claim_sotp_params_set_ex(uint32_t oem_transfer_mode, int64_t min_fw_ver_value)
{
    sotp_result_e status;

    tr_debug("Setting to SOTP: oem_transfer_mode: %" PRIu32 ", min_fw_ver_value: %" PRId64, oem_transfer_mode, min_fw_ver_value);

    //set Minimum FW Version Monotonic Counter (must be 64bit for the boot loader)
    status = sotp_data_store((const uint8_t *)&min_fw_ver_value, sizeof(int64_t), SOTP_TYPE_MIN_FW_VERSION);
    if (status != SOTP_SUCCESS) {
        tr_error("Failed storing SOTP_TYPE_MIN_FW_VERSION, status: %u, returning: %u",
                 status, MBED_ORC_FAILED_SETTING_MIN_FW_VERSION_TO_SOTP);
        return MBED_ORC_FAILED_SETTING_MIN_FW_VERSION_TO_SOTP;
    }

    //set Minimum OEM transfer mode flag (must be 32bit for the boot loader)
    status = sotp_data_store((const uint8_t *)&oem_transfer_mode, sizeof(uint32_t), SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED);
    if (status != SOTP_SUCCESS) {
        tr_error("Failed storing SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED, status: %u, returning: %u",
                 status, MBED_ORC_FAILED_SETTING_OEM_TRANSFER_MODE_TO_SOTP);
        return MBED_ORC_FAILED_SETTING_OEM_TRANSFER_MODE_TO_SOTP;
    }

    return MBED_ORC_SUCCESS;
}


bool OemRoleClaim::is_oem_role_claim_enabled()
{

    char enable_role_claim_data;
    size_t enable_role_claim_flag_size;

    //check status of enable_oem_role_claim flag
    load_kcm_param(oem_enable_role_claim_name, (uint8_t *)&enable_role_claim_data, &enable_role_claim_flag_size);
    if (enable_role_claim_flag_size != sizeof(uint8_t)) {
        tr_error("Failed loading %s from KCM, size: %zu, returning: %u",
                 oem_enable_role_claim_name, enable_role_claim_flag_size, false);
        return false;
    } else {
        tr_debug("Fetched %s, value: '%c'", oem_enable_role_claim_name, enable_role_claim_data);
    }

    if (enable_role_claim_data != '1') {
        tr_error("OEM role claim access forbidden!");
        return false;
    }

    return true;
}


void OemRoleClaim::InitResourcesValues()
{

    //max buffer for config params and sotp values
    uint8_t *value_buffer;
    size_t value_size = 0;
    sotp_result_e sotp_result;


    value_buffer = (uint8_t *)malloc(CERTIFICATE_BUFFER_SIZE);
    if (value_buffer == NULL) {
        tr_error("Failed to create Oem role Claim Object");
        return;
    }

    OemRoleClaim::OemRoleClaimResource_s *resource_items_iter = &oem_role_claim_resource_table[0];

    for (; resource_items_iter->resource_id != ID_END_OF_LIST; resource_items_iter++) {

        if (resource_items_iter->kcm_name != NULL) {    //KCM values
            load_kcm_param(resource_items_iter->kcm_name, value_buffer, &value_size);
        } else if (resource_items_iter->resource_id == ID_MIN_FW_VERSION_MONOTONIC_COUNTER) { //sotp value
            sotp_result =  sotp_data_retreive((uint8_t *)value_buffer, sizeof(uint64_t), &value_size, SOTP_TYPE_MIN_FW_VERSION);
            if (sotp_result != SOTP_SUCCESS) {
                value_size = 0;
            }
        }

        //set default values
        if (value_size != 0) {
            if ((resource_items_iter->resource_id == ID_VENDOR_ID) || (resource_items_iter->resource_id == ID_CLASS_ID)) {
                size_t j = 0;
                const size_t buffer_size = 40;
                uint8_t buffer[buffer_size];

                for (size_t i = 0; i < value_size; i++) {
                    buffer[j++] = hex_table[(value_buffer[i] >> 4) & 0xF];
                    buffer[j++] = hex_table[(value_buffer[i] >> 0) & 0xF];
                }

                buffer[j] = '\0';
                set_resource_value(resource_items_iter->resource_id, buffer, value_size * 2);

            } else if (resource_items_iter->resource_id == ID_MIN_FW_VERSION_MONOTONIC_COUNTER) {
                char str[20];
                m2m::itoa_c(*(uint64_t *)value_buffer, str);
                set_resource_value(resource_items_iter->resource_id, (uint8_t *)str, strlen(str));
            } else {
                set_resource_value(resource_items_iter->resource_id, value_buffer, value_size);
            }
        }
    }

    free(value_buffer);
}


void create_oem_role_claim_object(void)
{
    //create OemRoleClaim object resources
    OemRoleClaim::OemRoleClaimResource_s *resource_items_iter = &OemRoleClaim::oem_role_claim_resource_table[0];
    pt_api_result_code_e retval;

    for (; resource_items_iter->resource_id != OemRoleClaim::ID_END_OF_LIST; resource_items_iter++) {
        /* In Mbed edge, the API creates the resources as their values are set. */
        retval = set_resource_value(resource_items_iter->resource_id, NULL, 0);
        if (retval != PT_API_SUCCESS) {
            printf("resource creation for %"PRIu16"/0/%"PRIu16"/0 failed with %d",
                   OEM_ROLE_CLAIM_OBJECT_VALUE, resource_items_iter->resource_id, retval);
            assert(0);
            // TODO: can we continue somehow?
        }

        // Skip ID_APPLY_OEM_ROLE_CLAIM as it uses execute_callback() instea od updated_callback()
        if (resource_items_iter->resource_id == OemRoleClaim::ID_APPLY_OEM_ROLE_CLAIM) {
            continue;
        }

        retval = edgeclient_set_value_update_callback(OEM_ROLE_CLAIM_OBJECT_VALUE, 0, resource_items_iter->resource_id, resource_items_iter->resource_cb.update);
        if (retval != PT_API_SUCCESS) {
            printf("resource update callback for %"PRIu16"/0/%"PRIu16"/0 failed with %d",
                   OEM_ROLE_CLAIM_OBJECT_VALUE, resource_items_iter->resource_id, retval);
            assert(0);
            // TODO: can we continue somehow?
        }
    }

    retval = edgeclient_set_execute_callback(OEM_ROLE_CLAIM_OBJECT_VALUE, 0, OemRoleClaim::ID_APPLY_OEM_ROLE_CLAIM, OemRoleClaim::apply_oem_role_claim_callback);
    if (retval != PT_API_SUCCESS) {
        printf("callback registration for %"PRIu16"/0/%"PRIu16"/0 failed with %d",
               OEM_ROLE_CLAIM_OBJECT_VALUE, OemRoleClaim::ID_APPLY_OEM_ROLE_CLAIM, retval);
        assert(0);
        // TODO: can we continue somehow?
    }

    retval = edgeclient_set_delayed_response(NULL, OEM_ROLE_CLAIM_OBJECT_VALUE, 0, OemRoleClaim::ID_APPLY_OEM_ROLE_CLAIM, true);
    if (retval != PT_API_SUCCESS) {
        printf("enabling delayed response for %"PRIu16"/0/%"PRIu16"/0 failed with %d",
               OEM_ROLE_CLAIM_OBJECT_VALUE, OemRoleClaim::ID_APPLY_OEM_ROLE_CLAIM, retval);
        assert(0);
        // TODO: can we continue somehow?
    }

    // there is no way to delete a tasklet, but we can re-use the old one if one exists
    if (_tasklet < 0) {
        _tasklet = eventOS_event_handler_create(oem_tasklet_event_handler_wrapper, OEM_TASKLET_INIT_EVENT);

        if (_tasklet < 0) {
            tr_error("Unable to create tasklet");
            return;
        }
    }

    OemRoleClaim::InitResourcesValues();
}

// Preserve the initial error, but let the flow continue
#define ORC_SET_ERROR_VALUE_IF_NOT_ALREADY_SET(_orc_error) \
    if (status == MBED_ORC_SUCCESS) { \
        status = _orc_error; \
    }

uint32_t OemRoleClaim::FactoryResetHander(void)
{

    sotp_result_e sotp_status;
    kcm_status_e kcm_status;
    uint32_t sotp_oem_transfer_mode_flag;
    uint64_t min_fw_version_monotonic_counter;
    size_t min_fw_version_monotonic_counter_size;
    size_t oem_transfer_mode_flag_actual_size;
    size_t min_fw_version_monotonic_counter_actual_size;;
    uint32_t kcm_oem_transfer_mode_flag;
    size_t kcm_oem_transfer_mode_flag_size;
    uint32_t status = MBED_ORC_SUCCESS;

    // Read Oem transfer mode flag from  SOTP (may not exist)
    sotp_status = sotp_data_retreive((uint8_t *)&sotp_oem_transfer_mode_flag,
                                     sizeof(uint32_t),
                                     &oem_transfer_mode_flag_actual_size,
                                     SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED);
    if (sotp_status != SOTP_SUCCESS) {
        tr_warning("Failed retrieving SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED, status: %d", sotp_status);
    }

    tr_debug("sotp_oem_transfer_mode_flag: %" PRIu32, sotp_oem_transfer_mode_flag);

    // Load advantech.OemTransferred flag from KCM (may not exist)
    load_kcm_param(oem_transferred_name, (uint8_t *)&kcm_oem_transfer_mode_flag, &kcm_oem_transfer_mode_flag_size);
    if (kcm_oem_transfer_mode_flag_size == 0) {
        tr_warning("WARNING: %s was not found in KCM", oem_transferred_name);
    }

    // advantech.OemTransferred false or does not exist and Oem transfer mode was activated
    // A situation that will happen only after two consecutive factory reset with no update in between
    if (((kcm_oem_transfer_mode_flag_size == 0) || (kcm_oem_transfer_mode_flag == false)) && (sotp_oem_transfer_mode_flag == true)) {
        kcm_oem_transfer_mode_flag = true;
        kcm_oem_transfer_mode_flag_size = sizeof(uint32_t);

        // Set KCM advantech.MinimumOemFwVersionCounter to the value of "Minimum FW Version Monotonic Counter" stored in SOTP,
        // otherwise after two consecutive Factory Resets the "Minimum FW Version Monotonic Counter" is zeroed
        sotp_status = sotp_data_retreive((uint8_t *)&min_fw_version_monotonic_counter,
                                         sizeof(uint64_t),
                                         &min_fw_version_monotonic_counter_actual_size,
                                         SOTP_TYPE_MIN_FW_VERSION);
        if (sotp_status != SOTP_SUCCESS) {
            tr_error("Failed retrieving SOTP_TYPE_MIN_FW_VERSION, status: %d, setting error: %u",
                     sotp_status, MBED_ORC_FAILED_GETTING_MIN_FW_VERSION_FROM_SOTP);
            ORC_SET_ERROR_VALUE_IF_NOT_ALREADY_SET(MBED_ORC_FAILED_GETTING_MIN_FW_VERSION_FROM_SOTP);
        }

        tr_debug("min_fw_version_monotonic_counter: %" PRIu64, min_fw_version_monotonic_counter);

        kcm_status = update_kcm_param(oem_min_fw_ver_monotonic_counter, (uint8_t *)&min_fw_version_monotonic_counter, sizeof(uint64_t));
        if (kcm_status != KCM_STATUS_SUCCESS) {
            tr_error("Failed updating KCM value: %s, status: %u, setting error: %u",
                     oem_min_fw_ver_monotonic_counter, kcm_status, MBED_ORC_FAILED_SETTING_MIN_OEM_FW_VERSION_TO_KCM);
            ORC_SET_ERROR_VALUE_IF_NOT_ALREADY_SET(MBED_ORC_FAILED_SETTING_MIN_OEM_FW_VERSION_TO_KCM);
        }
    }

    // KCM advantech.OemTransferred == "True"
    if ((kcm_oem_transfer_mode_flag_size == sizeof(uint32_t)) && (kcm_oem_transfer_mode_flag == true)) {

        //set SOTP "OEM transfer mode" flag
        sotp_oem_transfer_mode_flag = true;
        sotp_status = sotp_data_store((const uint8_t *)&sotp_oem_transfer_mode_flag,
                                      sizeof(uint32_t),
                                      SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED);
        if (sotp_status != SOTP_SUCCESS) {
            tr_error("Failed storing SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED, status: %u, setting error: %u",
                     sotp_status, MBED_ORC_FAILED_SETTING_OEM_TRANSFER_MODE_TO_SOTP);
            ORC_SET_ERROR_VALUE_IF_NOT_ALREADY_SET(MBED_ORC_FAILED_SETTING_OEM_TRANSFER_MODE_TO_SOTP);
        }

        // Get oem_min_fw_ver_monotonic_counter from KCM (may not exist)
        load_kcm_param(oem_min_fw_ver_monotonic_counter, (uint8_t *)&min_fw_version_monotonic_counter, &min_fw_version_monotonic_counter_size);
        if (min_fw_version_monotonic_counter_size == 0) {
            tr_warning("WARNING: %s was not found in KCM, resetting min_fw_version_monotonic_counter to '0'",
                       oem_min_fw_ver_monotonic_counter);

            // reset min_fw_version_monotonic_counter to 0
            min_fw_version_monotonic_counter = 0;
        }

        // Write min_fw_version_monotonic_counter to SOTP
        sotp_status = sotp_data_store((const uint8_t *)&min_fw_version_monotonic_counter,
                                      sizeof(uint64_t),
                                      SOTP_TYPE_MIN_FW_VERSION);
        if (sotp_status != SOTP_SUCCESS) {
            tr_error("Failed storing SOTP_TYPE_MIN_FW_VERSION, status: %u, setting error: %u",
                     sotp_status, MBED_ORC_FAILED_SETTING_MIN_FW_VERSION_TO_SOTP);
            ORC_SET_ERROR_VALUE_IF_NOT_ALREADY_SET(MBED_ORC_FAILED_SETTING_MIN_FW_VERSION_TO_SOTP);
        }

        tr_debug("min_fw_version_monotonic_counter: %" PRIu64, min_fw_version_monotonic_counter);

    } else {

        //sotp parameters reset
        status = oem_sotp_params_reset();
        if (status != MBED_ORC_SUCCESS) {
            tr_error("sotp params reset failed with status: %" PRIu32, status);
            ORC_SET_ERROR_VALUE_IF_NOT_ALREADY_SET(status);
        } else {
            tr_debug("sotp params reset compelted successfully");
        }
    }

    tr_debug("FactoryResetHander returning with status: %" PRIu32, status);
    return status;
}
