/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */

#include <time.h>
#include "edge-client/edge_client.h"
#include "edge-client/oem_role_claim.h"
#include "mbed-trace/mbed_trace.h"
#include "edge-core/edge_server_customer_code.h"
#define TRACE_GROUP "escstmr"

bool edgeserver_execute_rfs_customer_code(edgeclient_request_context_t *request_ctx)
{
    tr_info("edgeserver_execute_rfs_customer_code %d/%d/%d",
            request_ctx->object_id,
            request_ctx->object_instance_id,
            request_ctx->resource_id);

    // Start a asynchronous factory reset sequence.
    // Because we are blocking on the next line, this is actually more of a synchronous operation.
    // Factory reset was implemented as asynchronous operation because the original idea was that
    // factory reset is initiated from resource execute callback function where you cannot block
    // for long time (>10ms).
    StartFactoryReset();

    // The OEM Role Claim factory reset is an asynchronous operation.
    // The edge server needs to send the result of that operation by calling edgeclient_send_delayed_response()
    // after this function returns.
    // Therefore, this function needs to wait for the asynchronous operation to complete before returning.
    // This is currently done with a loop that polls is_factory_reset_in_progress() return value.
    // This polling delay should probably be upgraded to more conventional semaphore wait.
    struct timespec delay;
    delay.tv_sec = 0;
    delay.tv_nsec = 100 * 1000 * 1000; // 100 ms sleep
    while (is_factory_reset_in_progress()) {
        nanosleep(&delay, NULL);
    }

    return true;
}

