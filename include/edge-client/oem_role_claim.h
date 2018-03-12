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


#ifndef OEM_ROLE_CLAIM_RESOURCE_H
#define OEM_ROLE_CLAIM_RESOURCE_H

#include <stdint.h>
#include "sotp.h"

#ifdef __cplusplus
namespace OemRoleClaim
{

const char oem_sw_manufacturer_parameter_name[] =             "advantech.SwManufacturer";
const char oem_sw_model_num_parameter_name[] =                "advantech.SwModelNumber";
const char oem_sw_device_type_parameter_name[] =              "advantech.SwDeviceType";
const char oem_vendor_id_name[] =                             "mbed.VendorId";
const char oem_class_id_name[] =                              "mbed.ClassId";
const char oem_enable_role_claim_name[] =                     "advantech.EnableOemRoleClaim";
const char oem_transferred_name[] =                           "advantech.OemTransferred";
const char oem_min_fw_ver_monotonic_counter[] =               "advantech.MinimumOemFwVersionMontonicCounter";


#define CONFIG_PARAMS_BUFFER_SIZE                 128
#define CERTIFICATE_BUFFER_SIZE                   2048
#define UUID5_SIZE_IN_BYTES                       16

#define MIN_LENGTH(X,Y) ((X) < (Y) ? (X) : (Y))

//resource updates indicator bits
#define SW_MANUFACTURER_BIT                                               (1 << 0)
#define SW_MODEL_NUMBER_BIT                                               (1 << 1)
#define SW_DEVICE_TYPE_BIT                                                (1 << 2)
#define VENDOR_ID_BIT                                                     (1 << 3)
#define CLASS_ID_BIT                                                      (1 << 4)
#define MIN_FW_VERSION_MONOTONIC_COUNTER_BIT                              (1 << 5)
#define UPDATE_AUTH_CERT_BIT                                              (1 << 6)
#define ENABLE_OEM_ROLE_CLAIM_BIT                                         (1 << 7)

#define ALL_RESOURCES_UPDATED_MASK  (SW_MANUFACTURER_BIT | SW_MODEL_NUMBER_BIT | SW_DEVICE_TYPE_BIT | VENDOR_ID_BIT |    \
                                     CLASS_ID_BIT | MIN_FW_VERSION_MONOTONIC_COUNTER_BIT | UPDATE_AUTH_CERT_BIT | ENABLE_OEM_ROLE_CLAIM_BIT)




uint32_t FactoryResetHander(void);

void InitResourcesValues(void);

}

extern "C" {

void create_oem_role_claim_object();

#endif // __cplusplus

// Error Codes
#define MBED_ORC_SUCCESS                                           0
#define MBED_ORC_FEATURE_DISABLED                               1000
#define MBED_ORC_SOME_RESOURCES_NOT_YET_UPDATED                 1001
#define MBED_ORC_FAILED_GETTING_MBED_MANUFACTURER_FROM_KCM      1002
#define MBED_ORC_FAILED_GETTING_SW_MANUFACTURER_FROM_KCM        1003
#define MBED_ORC_FAILED_GETTING_SW_MODEL_NUMBER_FROM_KCM        1004
#define MBED_ORC_FAILED_SETTING_MIN_OEM_FW_VERSION_TO_KCM       1005
#define MBED_ORC_FAILED_SETTING_VALUE_TO_KCM                    1006
#define MBED_ORC_FAILED_SETTING_MIN_FW_VERSION_TO_SOTP          1007
#define MBED_ORC_FAILED_GETTING_MIN_FW_VERSION_FROM_SOTP        1008
#define MBED_ORC_FAILED_SETTING_OEM_TRANSFER_MODE_TO_SOTP       1009
#define MBED_ORC_FAILED_SETTING_OEM_TRANSFER_FLAG_TO_KCM        1010
#define MBED_ORC_SW_MANUFACTURER_AND_SW_MODEL_NUMBER_UNCHANGED  1011
#define MBED_ORC_INIT_FW_MANAGER_ERROR                          1012
#define MBED_ORC_GET_ACTIVE_FW_DETAILS_ERROR                    1013
#define MBED_ORC_GET_ACTIVE_FW_DETAILS_UNKNOWN_ERROR            1014
#define MBED_ORC_KCM_FACTORY_RESET_FAILED                       1015

#ifdef __cplusplus
}
#endif // __cplusplus

#endif
