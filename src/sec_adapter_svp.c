/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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

Sec_Result SecOpaqueBuffer_Malloc(SEC_SIZE bufLength, Sec_OpaqueBufferHandle** handle) {
    if (bufLength == 0) {
        SEC_LOG_ERROR("Argument `length' has value of 0");
        return SEC_RESULT_FAILURE;
    }
    if (handle == NULL) {
        SEC_LOG_ERROR("Argument `handle' has value of null");
        return SEC_RESULT_FAILURE;
    }

    *handle = (Sec_OpaqueBufferHandle*) calloc(1, sizeof(Sec_OpaqueBufferHandle));
    if (*handle == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    sa_status status = sa_svp_memory_alloc(&(*handle)->svp_memory, bufLength);
    if (status != SA_STATUS_OK) {
        SEC_LOG_ERROR("sa_svp_memory_alloc failed");
        free(*handle);
        CHECK_STATUS(status)
    }

    (*handle)->size = bufLength;
    status = sa_svp_buffer_create(&(*handle)->svp_buffer, (*handle)->svp_memory, bufLength);
    if (status != SA_STATUS_OK) {
        SEC_LOG_ERROR("sa_svp_buffer_create failed");
        sa_svp_memory_free((*handle)->svp_memory);
        free(*handle);
        CHECK_STATUS(status)
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result Sec_OpaqueBufferWrite(Sec_OpaqueBufferHandle* opaqueBufferHandle, SEC_SIZE offset, void* data,
        SEC_SIZE length) {
    return SecOpaqueBuffer_Write(opaqueBufferHandle, offset, data, length);
}

Sec_Result SecOpaqueBuffer_Write(Sec_OpaqueBufferHandle* opaqueBufferHandle, SEC_SIZE offset, SEC_BYTE* data,
        SEC_SIZE length) {
    if (opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Invalid handle");
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

    size_t out_offset = offset;
    sa_status status = sa_svp_buffer_write((*opaqueBufferHandle).svp_buffer, &out_offset, data, length);
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

    size_t out_off = out_offset;
    size_t in_off = in_offset;
    sa_status status = sa_svp_buffer_copy(outOpaqueBufferHandle->svp_buffer, &out_off, inOpaqueBufferHandle->svp_buffer,
            &in_off, num_to_copy);
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

Sec_Result SecOpaqueBuffer_Check(Sec_DigestAlgorithm digestAlgorithm, Sec_OpaqueBufferHandle* opaqueBufferHandle,
        SEC_SIZE length, SEC_BYTE* expected, SEC_SIZE expectedLength) {
    if (opaqueBufferHandle == NULL) {
        SEC_LOG_ERROR("Null pointer arg encountered");
        return SEC_RESULT_FAILURE;
    }

    if (expected == NULL) {
        SEC_LOG_ERROR("Null pointer arg encountered");
        return SEC_RESULT_FAILURE;
    }

    sa_digest_algorithm algorithm;
    switch (digestAlgorithm) {
        case SEC_DIGESTALGORITHM_SHA1:
            algorithm = SA_DIGEST_ALGORITHM_SHA1;
            break;

        case SEC_DIGESTALGORITHM_SHA256:
            algorithm = SA_DIGEST_ALGORITHM_SHA256;
            break;

        default:
            return SEC_RESULT_INVALID_PARAMETERS;
    }

    sa_status status = sa_svp_buffer_check(opaqueBufferHandle->svp_buffer, 0, length, algorithm, expected,
            expectedLength);
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
