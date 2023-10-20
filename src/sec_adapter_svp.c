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

#include "sec_security_svp.h"

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

    sa_status status = sa_svp_buffer_create(&(*opaqueBufferHandle)->svp_buffer, svp_memory, bufLength);
    if (status != SA_STATUS_OK) {
        SEC_LOG_ERROR("sa_svp_buffer_create failed");
        CHECK_STATUS(status)
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

    if (svp_memory == NULL) {
        SEC_LOG_ERROR("svp_memory is NULL");
        return SEC_RESULT_FAILURE;
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
    sa_status status = sa_svp_buffer_write((*opaqueBufferHandle).svp_buffer, data, length, &svp_offset, 1);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

Sec_Result Sec_OpaqueBufferFree(Sec_OpaqueBufferHandle* opaqueBufferHandle, void* params) {
    return SecOpaqueBuffer_Free(opaqueBufferHandle);
}

Sec_Result SecOpaqueBuffer_Free(Sec_OpaqueBufferHandle* opaqueBufferHandle) {
    if (opaqueBufferHandle != NULL) {
        sa_svp_buffer_free(opaqueBufferHandle->svp_buffer);
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
    sa_status status = sa_svp_buffer_copy(outOpaqueBufferHandle->svp_buffer, inOpaqueBufferHandle->svp_buffer,
            &svp_offset, 1);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecOpaqueBuffer_Release(Sec_OpaqueBufferHandle* opaqueBufferHandle, Sec_ProtectedMemHandle** svpHandle) {
    if (svpHandle == NULL || opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Null pointer arg encountered");
        return SEC_RESULT_FAILURE;
    }

    size_t out_length;
    sa_status status = sa_svp_buffer_release(svpHandle, &out_length, opaqueBufferHandle->svp_buffer);
    CHECK_STATUS(status)
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

    sa_status status = sa_svp_buffer_copy(outOpaqueBufferHandle->svp_buffer, inOpaqueBufferHandle->svp_buffer,
            svp_offsets, numOfIndexes);
    SEC_FREE(svp_offsets);
    CHECK_STATUS(status)
    return SEC_RESULT_SUCCESS;
}
