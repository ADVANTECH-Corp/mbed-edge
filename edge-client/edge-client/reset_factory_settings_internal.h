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

#ifndef RESET_FACTORY_SETTINGS_INTERNAL_H
#define RESET_FACTORY_SETTINGS_INTERNAL_H
#ifdef BUILD_TYPE_TEST
#include <event2/event.h>

#ifdef __cplusplus
extern "C" {
#endif

void rfs_reset_factory_settings_request_cb(evutil_socket_t fd, short what, void *arg);
void rfs_reset_factory_settings_response_cb(evutil_socket_t fd, short what, void *arg);
#ifdef __cplusplus
}
#endif

#endif
#endif
