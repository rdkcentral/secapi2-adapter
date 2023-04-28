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

typedef struct svp_processor_buffer_struct {
    Sec_ProcessorHandle* processorHandle;
    sa_svp_buffer svp_buffer;
    struct svp_processor_buffer_struct* next;
} svp_processor_buffer;

struct Sec_OpaqueBufferHandle_struct {
    void* svp_memory;
    size_t size;
    svp_processor_buffer* handles;
    pthread_mutex_t mutex;
};

typedef struct {
    size_t offset_in_src;
    size_t offset_in_target;
    size_t bytes_to_copy;
} SEC_CopyIndex;

Sec_Result SecOpaqueBuffer_CopyByIndex(Sec_OpaqueBufferHandle* outOpaqueBufferHandle,
        Sec_OpaqueBufferHandle* inOpaqueBufferHandle, SEC_CopyIndex* copyIndexArray, SEC_SIZE numOfIndexes);
Sec_Result SecOpaqueBuffer_Create(Sec_OpaqueBufferHandle** opaqueBufferHandle, void* svp_memory, SEC_SIZE bufLength);
Sec_Result SecOpaqueBuffer_Malloc2(SEC_SIZE bufLength, Sec_ProcessorHandle* processorHandle,
        Sec_OpaqueBufferHandle** opaqueBufferHandle);
sa_svp_buffer get_svp_buffer(Sec_ProcessorHandle* processorHandle, Sec_OpaqueBufferHandle* opaqueBufferHandle);
void release_svp_buffer(Sec_ProcessorHandle* processorHandle, Sec_OpaqueBufferHandle* opaqueBufferHandle);

#ifdef __cplusplus
}
#endif

#endif // SEC_SECURITY_SVP_H
