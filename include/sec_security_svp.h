/**
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SEC_SECURITY_SVP_H
#define SEC_SECURITY_SVP_H

#include "sa_types.h"
#include "sec_adapter_processor.h"
#include "sec_security.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

struct Sec_OpaqueBufferHandle_struct {
    sa_svp_buffer svp_buffer;
    void* svp_memory;
    size_t size;
};

typedef struct {
    size_t offset_in_src;
    size_t offset_in_target;
    size_t bytes_to_copy;
} SEC_CopyIndex;
#endif // SEC_SECURITY_SVP_H
