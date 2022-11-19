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

#include "svp.h"
#include "cipher.h"
#include "test_ctx.h"

#define MAX_BUFFER_SIZE (64 * 1024)

Sec_Result testOpaqueMalloc() {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle* opaqueBufferHandle = nullptr;
    SEC_BYTE input[MAX_BUFFER_SIZE];

    if (SecOpaqueBuffer_Malloc(sizeof(input), &opaqueBufferHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecOpaqueBuffer_Write(opaqueBufferHandle, 0, input, sizeof(input)) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Sec_OpaqueBufferWrite failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecOpaqueBuffer_Free(opaqueBufferHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Sec_OpaqueBufferFree failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testSecureBootEnabled() {
// SecCodeIntegrity_SecureBootEnabled is an unimplemented feature
#if 0
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecCodeIntegrity_SecureBootEnabled() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCodeIntegrity_SecureBootEnabled failed");
        return SEC_RESULT_FAILURE;
    }
#endif
    return SEC_RESULT_SUCCESS;
}

Sec_Result testSetTime() {
// SecSVP_SetTime is an unimplemented feature
#if 0
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecSVP_SetTime(time(nullptr)) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSVP_SetTime failed");
        return SEC_RESULT_FAILURE;
    }
#endif
    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeycheckOpaque(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandle;
    if ((keyHandle = ctx.provisionKey(id, loc, key, kc)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_CipherHandle* cipherHandle = nullptr;
    if (SecCipher_GetInstance(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, keyHandle,
                nullptr,
                &cipherHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> expected = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> input = opensslAesEcb(key, SEC_CIPHERMODE_ENCRYPT, SEC_FALSE, nullptr, expected);

    TestCtx::printHex("input", input);
    TestCtx::printHex("expected", expected);

    Sec_OpaqueBufferHandle* opaqueBufferHandle = nullptr;
    if (SecOpaqueBuffer_Malloc(256, &opaqueBufferHandle) != SEC_RESULT_SUCCESS) {
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecOpaqueBuffer_Write(opaqueBufferHandle, 0, &input[0], input.size()) != SEC_RESULT_SUCCESS) {
        SecOpaqueBuffer_Free(opaqueBufferHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("Sec_OpaqueBufferWrite failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecCipher_KeyCheckOpaque(cipherHandle, opaqueBufferHandle, SEC_AES_BLOCK_SIZE, &expected[0]) !=
            SEC_RESULT_SUCCESS) {
        SecOpaqueBuffer_Free(opaqueBufferHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("SecCipher_KeyCheckOpaque failed");
        return SEC_RESULT_FAILURE;
    }

    /* 2.2 checks for 'checkLength' arg */
    if (SecCipher_KeyCheckOpaque(cipherHandle, opaqueBufferHandle, 8, &expected[0]) != SEC_RESULT_SUCCESS) {
        SecOpaqueBuffer_Free(opaqueBufferHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("SecCipher_KeyCheckOpaque failed");
        return SEC_RESULT_FAILURE;
    }
    if (SecCipher_KeyCheckOpaque(cipherHandle, opaqueBufferHandle, 7, &expected[0]) == SEC_RESULT_SUCCESS) {
        SecOpaqueBuffer_Free(opaqueBufferHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("Expected SecCipher_KeyCheckOpaque to fail with checkLength < 8");
        return SEC_RESULT_FAILURE;
    }
    if (SecCipher_KeyCheckOpaque(cipherHandle, opaqueBufferHandle, 17, &expected[0]) == SEC_RESULT_SUCCESS) {
        SecOpaqueBuffer_Free(opaqueBufferHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("Expected SecCipher_KeyCheckOpaque to fail with checkLength > 16");
        return SEC_RESULT_FAILURE;
    }

    SecOpaqueBuffer_Free(opaqueBufferHandle);
    SecCipher_Release(cipherHandle);

    return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessOpaque(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm cipher_algorithm, int size) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandle;
    if ((keyHandle = ctx.provisionKey(id, loc, key, kc)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    Sec_CipherHandle* cipherHandle = nullptr;
    if (SecCipher_GetInstance(ctx.proc(), cipher_algorithm, SEC_CIPHERMODE_DECRYPT, keyHandle, &iv[0], &cipherHandle) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle* inOpaqueBufferHandle = nullptr;
    if (SecOpaqueBuffer_Malloc(size, &inOpaqueBufferHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        SecCipher_Release(cipherHandle);
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle* outOpaqueBufferHandle = nullptr;
    if (SecOpaqueBuffer_Malloc(size, &outOpaqueBufferHandle) != SEC_RESULT_SUCCESS) {
        SecOpaqueBuffer_Free(outOpaqueBufferHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_SIZE written = 0;

    SEC_BOOL last = size % 16 == 0 ? SEC_TRUE : SEC_FALSE;
    if (SecCipher_ProcessOpaque(cipherHandle, inOpaqueBufferHandle, outOpaqueBufferHandle, size, last, &written) !=
            SEC_RESULT_SUCCESS) {
        SecOpaqueBuffer_Free(inOpaqueBufferHandle);
        SecOpaqueBuffer_Free(outOpaqueBufferHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("SecCipher_ProcessOpaque failed");
        return SEC_RESULT_FAILURE;
    }

    SecOpaqueBuffer_Free(inOpaqueBufferHandle);
    SecOpaqueBuffer_Free(outOpaqueBufferHandle);
    SecCipher_Release(cipherHandle);

    return SEC_RESULT_SUCCESS;
}


Sec_Result testCopyOpaque() {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle* inOpaqueBufferHandle = nullptr;
    if (SecOpaqueBuffer_Malloc(256, &inOpaqueBufferHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle* outOpaqueBufferHandle = nullptr;
    if (SecOpaqueBuffer_Malloc(256, &outOpaqueBufferHandle) != SEC_RESULT_SUCCESS) {
        SecOpaqueBuffer_Free(inOpaqueBufferHandle);
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_BYTE tmp[128];
    if (SecOpaqueBuffer_Write(inOpaqueBufferHandle, 128, tmp, 128) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Write failed");
        SecOpaqueBuffer_Free(inOpaqueBufferHandle);
        SecOpaqueBuffer_Free(outOpaqueBufferHandle);
        return SEC_RESULT_FAILURE;
    }

    if (SecOpaqueBuffer_Copy(outOpaqueBufferHandle, 0, inOpaqueBufferHandle, 128, 128) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Copy failed");
        SecOpaqueBuffer_Free(inOpaqueBufferHandle);
        SecOpaqueBuffer_Free(outOpaqueBufferHandle);
        return SEC_RESULT_FAILURE;
    }

    SecOpaqueBuffer_Free(inOpaqueBufferHandle);
    SecOpaqueBuffer_Free(outOpaqueBufferHandle);

    return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessDataShiftOpaque(SEC_OBJECTID id, TestKey key, TestKc kc,
        Sec_StorageLoc loc) {
// SecCipher_ProcessCtrWithOpaqueDataShift is an unimplemented feature.
#if 0
    TestCtx ctx;
    Sec_Result result = SEC_RESULT_FAILURE;
    Sec_OpaqueBufferHandle *inputHandle1 = nullptr;
    Sec_OpaqueBufferHandle *inputHandle2 = nullptr;
    Sec_OpaqueBufferHandle *outputHandle = nullptr;
    SEC_SIZE written = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle *handle = nullptr;
    if ((handle = ctx.provisionKey(id, loc, key, kc)) == nullptr) {
        SEC_LOG_ERROR("ctx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    Sec_CipherHandle *cipherHandle = nullptr;
    if (!= SEC_RESULT_SUCCESS) SecCipher_GetInstance(ctx.proc(),
                                                    SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, handle,
                                                    &iv[0], &cipherHandle)) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        break;
    }

    if (SecOpaqueBuffer_Malloc(8, &inputHandle1) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        break;
    }

    if (SecOpaqueBuffer_Malloc(256 - 8, &inputHandle2) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        break;
    }

    if (SecOpaqueBuffer_Malloc(256, &outputHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        break;
    }

    if (!= SEC_RESULT_SUCCESS) SecCipher_ProcessOpaque(cipherHandle,
                                                      inputHandle1, outputHandle, 8, SEC_FALSE, &written)) {
        SEC_LOG_ERROR("SecCipher_ProcessOpaque failed");
        break;
    }

    if (!= SEC_RESULT_SUCCESS)
        SecCipher_ProcessCtrWithOpaqueDataShift(cipherHandle, inputHandle2, outputHandle, 256 - 8, &written, 8)) {
        SEC_LOG_ERROR("SecCipher_ProcessCtrWithOpaqueDataShift failed");
        break;
    }


    result = SEC_RESULT_SUCCESS;

        } while(false);


    if (inputHandle1)
        SecOpaqueBuffer_Free(inputHandle1);
    if (inputHandle2)
        SecOpaqueBuffer_Free(inputHandle2);
    if (outputHandle)
        SecOpaqueBuffer_Free(outputHandle);
    if (cipherHandle)
        SecCipher_Release(cipherHandle);

    return result;
#endif
    return SEC_RESULT_SUCCESS;
}
