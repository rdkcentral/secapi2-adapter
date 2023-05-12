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

#include "sa_svp.h"
#include "sec_security_svp.h" // NOLINT

sa_svp_buffer get_svp_buffer(Sec_ProcessorHandle* processorHandle, Sec_OpaqueBufferHandle* opaqueBufferHandle) {
    if (processorHandle == NULL || opaqueBufferHandle == NULL)
        return INVALID_HANDLE;

    // Look up the buffer for this processorHandle.
    pthread_mutex_lock(&opaqueBufferHandle->mutex);
    svp_processor_buffer* next_processor_buffer = opaqueBufferHandle->handles;
    svp_processor_buffer* previous_processor_buffer = NULL;
    while (next_processor_buffer != NULL) {
        if (next_processor_buffer->processorHandle == processorHandle) {
            pthread_mutex_unlock(&opaqueBufferHandle->mutex);
            return next_processor_buffer->svp_buffer;
        }

        previous_processor_buffer = next_processor_buffer;
        next_processor_buffer = next_processor_buffer->next;
    }

    // Not found, so create a new one.
    sa_svp_buffer svp_buffer;
    if (sa_invoke(processorHandle, SA_SVP_BUFFER_CREATE, &svp_buffer, opaqueBufferHandle->svp_memory,
                opaqueBufferHandle->size) != SA_STATUS_OK) {
        SEC_LOG_ERROR("sa_svp_buffer_create failed");
        return INVALID_HANDLE;
    }

    next_processor_buffer = (svp_processor_buffer*) calloc(1, sizeof(svp_processor_buffer));
    if (previous_processor_buffer == NULL)
        opaqueBufferHandle->handles = next_processor_buffer;
    else
        previous_processor_buffer->next = next_processor_buffer;

    next_processor_buffer->processorHandle = processorHandle;
    next_processor_buffer->svp_buffer = svp_buffer;
    pthread_mutex_unlock(&opaqueBufferHandle->mutex);

    // Register this opaqueBufferHandle with processorHandle for later clean up.
    pthread_mutex_lock(&processorHandle->mutex);
    opaque_buffer_handle_entry* opaque_buffer_handle =
            (opaque_buffer_handle_entry*) calloc(1, sizeof(opaque_buffer_handle_entry));
    opaque_buffer_handle->opaqueBufferHandle = opaqueBufferHandle;
    opaque_buffer_handle->next = processorHandle->opaque_buffer_handle;
    processorHandle->opaque_buffer_handle = opaque_buffer_handle;
    pthread_mutex_unlock(&processorHandle->mutex);

    return next_processor_buffer->svp_buffer;
}

void release_svp_buffer(Sec_ProcessorHandle* processorHandle, Sec_OpaqueBufferHandle* opaqueBufferHandle) {
    if (processorHandle == NULL || opaqueBufferHandle == NULL)
        return;

    // Find the buffer for this processorHandle and release it.
    pthread_mutex_lock(&opaqueBufferHandle->mutex);
    svp_processor_buffer* next_processor_buffer = opaqueBufferHandle->handles;
    svp_processor_buffer* previous_processor_buffer = NULL;
    while (next_processor_buffer != NULL) {
        if (next_processor_buffer->processorHandle == processorHandle) {
            if (previous_processor_buffer == NULL)
                opaqueBufferHandle->handles = next_processor_buffer->next;
            else
                previous_processor_buffer->next = next_processor_buffer->next;

            void* svp_memory;
            size_t svp_size;
            sa_invoke(processorHandle, SA_SVP_BUFFER_RELEASE, &svp_memory, &svp_size,
                    next_processor_buffer->svp_buffer);
            free(next_processor_buffer);
            break;
        }

        previous_processor_buffer = next_processor_buffer;
        next_processor_buffer = next_processor_buffer->next;
    }

    pthread_mutex_unlock(&opaqueBufferHandle->mutex);

    // Unregister this opaqueBufferHandle from the processorHandle.
    pthread_mutex_lock(&processorHandle->mutex);
    opaque_buffer_handle_entry* next_opaque_buffer_handle = processorHandle->opaque_buffer_handle;
    opaque_buffer_handle_entry* previous_opaque_buffer_handle = NULL;
    while (next_opaque_buffer_handle != NULL) {
        if (next_opaque_buffer_handle->opaqueBufferHandle == opaqueBufferHandle) {
            if (previous_opaque_buffer_handle == NULL)
                processorHandle->opaque_buffer_handle = next_opaque_buffer_handle->next;
            else
                previous_opaque_buffer_handle->next = next_opaque_buffer_handle->next;

            free(next_opaque_buffer_handle);
            break;
        }

        previous_opaque_buffer_handle = next_opaque_buffer_handle;
        next_opaque_buffer_handle = next_opaque_buffer_handle->next;
    }

    pthread_mutex_unlock(&processorHandle->mutex);
}

// Deprecated
Sec_Result Sec_OpaqueBufferMalloc(SEC_SIZE bufLength, void** handle, void* params) {
    return SecOpaqueBuffer_Malloc(bufLength, (Sec_OpaqueBufferHandle**) handle);
}

Sec_Result SecOpaqueBuffer_Create(Sec_OpaqueBufferHandle** opaqueBufferHandle, void* svp_memory, SEC_SIZE bufLength) {
    if (opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Argument `opaqueBufferHandle' has value of null");
        return SEC_RESULT_FAILURE;
    }

    if (svp_memory == NULL) {
        SEC_LOG_ERROR("Argument `svp_memory' has value of null");
        return SEC_RESULT_FAILURE;
    }

    *opaqueBufferHandle = (Sec_OpaqueBufferHandle*) calloc(1, sizeof(Sec_OpaqueBufferHandle));
    if (*opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    if (pthread_mutex_init(&(*opaqueBufferHandle)->mutex, NULL) != 0) {
        SEC_LOG_ERROR("Error initializing mutex");
        free(*opaqueBufferHandle);
        return SEC_RESULT_FAILURE;
    }

    (*opaqueBufferHandle)->svp_memory = svp_memory;
    (*opaqueBufferHandle)->size = bufLength;
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecOpaqueBuffer_Malloc(SEC_SIZE bufLength, Sec_OpaqueBufferHandle** opaqueBufferHandle) {
    if (bufLength == 0) {
        SEC_LOG_ERROR("Argument `bufLength' has value of 0");
        return SEC_RESULT_FAILURE;
    }

    if (opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Argument `opaqueBufferHandle' has value of null");
        return SEC_RESULT_FAILURE;
    }

    void* svp_memory = NULL;
    sa_status status = sa_svp_memory_alloc(&svp_memory, bufLength);
    if (status != SA_STATUS_OK) {
        SEC_LOG_ERROR("sa_svp_memory_alloc failed");
        CHECK_STATUS(status)
    }

    Sec_Result result = SecOpaqueBuffer_Create(opaqueBufferHandle, svp_memory, bufLength);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Create failed");
        sa_svp_memory_free(svp_memory);
        return result;
    }

    return result;
}

Sec_Result Sec_OpaqueBufferWrite(Sec_OpaqueBufferHandle* opaqueBufferHandle, SEC_SIZE offset, void* data,
        SEC_SIZE length) {
    return SecOpaqueBuffer_Write(opaqueBufferHandle, offset, data, length);
}

Sec_Result SecOpaqueBuffer_Write(Sec_OpaqueBufferHandle* opaqueBufferHandle, SEC_SIZE offset, SEC_BYTE* data,
        SEC_SIZE length) {
    if (opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Invalid opaqueBufferHandle");
        return SEC_RESULT_INVALID_HANDLE;
    }

    if (data == NULL) {
        SEC_LOG_ERROR("Argument `data' has value of null");
        return SEC_RESULT_FAILURE;
    }

    if (length == 0) {
        SEC_LOG_ERROR("Argument `length' has value of 0");
        return SEC_RESULT_FAILURE;
    }

    sa_svp_offset svp_offset = {offset, 0, length};
    if (opaqueBufferHandle->handles != NULL) {
        sa_status status = sa_invoke(opaqueBufferHandle->handles->processorHandle, SA_SVP_BUFFER_WRITE,
                opaqueBufferHandle->handles->svp_buffer, data, (size_t) length, &svp_offset, 1);
        CHECK_STATUS(status)
    } else {
        sa_svp_buffer svp_buffer;
        if (sa_svp_buffer_create(&svp_buffer, opaqueBufferHandle->svp_memory,
                    opaqueBufferHandle->size) != SA_STATUS_OK) {
            SEC_LOG_ERROR("sa_svp_buffer_create failed");
            return SEC_RESULT_FAILURE;
        }

        sa_status status = sa_svp_buffer_write(svp_buffer, data, length, &svp_offset, 1);
        void* svp_memory;
        size_t svp_size;
        sa_svp_buffer_release(&svp_memory, &svp_size, svp_buffer);
        CHECK_STATUS(status)
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result Sec_OpaqueBufferFree(Sec_OpaqueBufferHandle* opaqueBufferHandle, void* params) {
    return SecOpaqueBuffer_Free(opaqueBufferHandle);
}

Sec_Result SecOpaqueBuffer_Free(Sec_OpaqueBufferHandle* opaqueBufferHandle) {
    if (opaqueBufferHandle != NULL) {
        while (opaqueBufferHandle->handles != NULL)
            release_svp_buffer(opaqueBufferHandle->handles->processorHandle, opaqueBufferHandle);

        sa_svp_memory_free(opaqueBufferHandle->svp_memory);
        pthread_mutex_destroy(&opaqueBufferHandle->mutex);
        SEC_FREE(opaqueBufferHandle);
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecOpaqueBuffer_Copy(Sec_OpaqueBufferHandle* outOpaqueBufferHandle, SEC_SIZE out_offset,
        Sec_OpaqueBufferHandle* inOpaqueBufferHandle, SEC_SIZE in_offset, SEC_SIZE num_to_copy) {
    if (outOpaqueBufferHandle == NULL || inOpaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Null pointer arg encountered");
        return SEC_RESULT_FAILURE;
    }

    sa_svp_offset svp_offset = {out_offset, in_offset, num_to_copy};
    if (outOpaqueBufferHandle->handles != NULL) {
        sa_svp_buffer in_svp_buffer = get_svp_buffer(outOpaqueBufferHandle->handles->processorHandle,
                inOpaqueBufferHandle);
        if (in_svp_buffer == INVALID_HANDLE)
            return SEC_RESULT_FAILURE;

        sa_status status = sa_invoke(outOpaqueBufferHandle->handles->processorHandle, SA_SVP_BUFFER_COPY,
                outOpaqueBufferHandle->handles->svp_buffer, in_svp_buffer, &svp_offset, (size_t) 1);
        CHECK_STATUS(status)
    } else {
        void* svp_memory;
        size_t svp_size;
        sa_svp_buffer out_svp_buffer;
        if (sa_svp_buffer_create(&out_svp_buffer, outOpaqueBufferHandle->svp_memory,
                    outOpaqueBufferHandle->size) != SA_STATUS_OK) {
            SEC_LOG_ERROR("sa_svp_buffer_create failed");
            return SEC_RESULT_FAILURE;
        }

        sa_svp_buffer in_svp_buffer;
        if (sa_svp_buffer_create(&in_svp_buffer, inOpaqueBufferHandle->svp_memory,
                    inOpaqueBufferHandle->size) != SA_STATUS_OK) {
            SEC_LOG_ERROR("sa_svp_buffer_create failed");
            sa_svp_buffer_release(&svp_memory, &svp_size, out_svp_buffer);
            return SEC_RESULT_FAILURE;
        }

        sa_status status = sa_svp_buffer_copy(out_svp_buffer, in_svp_buffer, &svp_offset, (size_t) 1);
        sa_svp_buffer_release(&svp_memory, &svp_size, out_svp_buffer);
        sa_svp_buffer_release(&svp_memory, &svp_size, in_svp_buffer);
        CHECK_STATUS(status)
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecOpaqueBuffer_Release(Sec_OpaqueBufferHandle* opaqueBufferHandle, Sec_ProtectedMemHandle** svpHandle) {
    if (svpHandle == NULL || opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Null pointer arg encountered");
        return SEC_RESULT_FAILURE;
    }

    while (opaqueBufferHandle->handles != NULL)
        release_svp_buffer(opaqueBufferHandle->handles->processorHandle, opaqueBufferHandle);

    *svpHandle = opaqueBufferHandle->svp_memory;
    SEC_FREE(opaqueBufferHandle);
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Checks secure boot configuration to verify that Secure Boot is enabled.
 */
Sec_Result SecCodeIntegrity_SecureBootEnabled(void) {
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecSVP_SetTime(time_t time) {
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecOpaqueBuffer_CopyByIndex(Sec_OpaqueBufferHandle* outOpaqueBufferHandle,
        Sec_OpaqueBufferHandle* inOpaqueBufferHandle, SEC_CopyIndex* copyIndexArray, SEC_SIZE numOfIndexes) {

    if (inOpaqueBufferHandle == NULL || outOpaqueBufferHandle == NULL || copyIndexArray == NULL) {
        SEC_LOG_ERROR("Null pointer arg encountered");
        return SEC_RESULT_FAILURE;
    }

    sa_svp_offset* svp_offsets = calloc(1, sizeof(sa_svp_offset) * numOfIndexes);
    if (svp_offsets == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    for (int i = 0; i < numOfIndexes; i++) {
        svp_offsets[i].in_offset = copyIndexArray[i].offset_in_src;
        svp_offsets[i].out_offset = copyIndexArray[i].offset_in_target;
        svp_offsets[i].length = copyIndexArray[i].bytes_to_copy;
    }

    sa_status status;
    if (outOpaqueBufferHandle->handles != NULL) {
        sa_svp_buffer in_svp_buffer = get_svp_buffer(outOpaqueBufferHandle->handles->processorHandle,
                inOpaqueBufferHandle);
        if (in_svp_buffer == INVALID_HANDLE) {
            SEC_LOG_ERROR("sa_svp_buffer_create failed");
            SEC_FREE(svp_offsets);
            return SEC_RESULT_FAILURE;
        }

        status = sa_invoke(outOpaqueBufferHandle->handles->processorHandle, SA_SVP_BUFFER_COPY,
                outOpaqueBufferHandle->handles->svp_buffer, in_svp_buffer, svp_offsets, (size_t) numOfIndexes);
    } else {
        void* svp_memory;
        size_t svp_size;
        sa_svp_buffer out_svp_buffer;
        if (sa_svp_buffer_create(&out_svp_buffer, outOpaqueBufferHandle->svp_memory,
                    outOpaqueBufferHandle->size) != SA_STATUS_OK) {
            SEC_LOG_ERROR("sa_svp_buffer_create failed");
            SEC_FREE(svp_offsets);
            return SEC_RESULT_FAILURE;
        }

        sa_svp_buffer in_svp_buffer;
        if (sa_svp_buffer_create(&in_svp_buffer, inOpaqueBufferHandle->svp_memory,
                    inOpaqueBufferHandle->size) != SA_STATUS_OK) {
            SEC_LOG_ERROR("sa_svp_buffer_create failed");
            sa_svp_buffer_release(&svp_memory, &svp_size, out_svp_buffer);
            SEC_FREE(svp_offsets);
            return SEC_RESULT_FAILURE;
        }

        status = sa_svp_buffer_copy(out_svp_buffer, in_svp_buffer, svp_offsets, (size_t) numOfIndexes);
        sa_svp_buffer_release(&svp_memory, &svp_size, out_svp_buffer);
        sa_svp_buffer_release(&svp_memory, &svp_size, in_svp_buffer);
    }

    SEC_FREE(svp_offsets);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}
