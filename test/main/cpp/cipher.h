/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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

#ifndef CIPHER_H
#define CIPHER_H

#include "sec_security.h"
#include "test_creds.h"

Sec_Result testCipherSingle(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace = SEC_FALSE);

Sec_Result testCipherSingle(SEC_OBJECTID id, TestKey pub, TestKey priv, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace = SEC_FALSE);

Sec_Result testCipherMult(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace = SEC_FALSE,
        SEC_BOOL testCtrRollover = SEC_FALSE);

Sec_Result testCipherMult(SEC_OBJECTID id, TestKey pub, TestKey priv, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, const std::vector<SEC_SIZE>& inputSizes,
        SEC_BOOL inplace = SEC_FALSE);

Sec_Result testCipherBandwidth(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, SEC_SIZE inputSize, SEC_SIZE intervalS);

Sec_Result testCipherBandwidthSingleCipher(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_SIZE intervalS);

Sec_Result cipherEncDecSingle(TestCtx* ctx, SEC_OBJECTID id, Sec_CipherAlgorithm alg, SEC_SIZE inputSize,
        SEC_BOOL inplace = SEC_FALSE);

Sec_Result cipherEncDecMult(TestCtx* ctx, SEC_OBJECTID id, Sec_CipherAlgorithm alg,
        const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace = SEC_FALSE);

Sec_Result cipherEncDecSingle(TestCtx* ctx, SEC_OBJECTID id_pub, SEC_OBJECTID id_priv, Sec_CipherAlgorithm alg,
        SEC_SIZE inputSize, SEC_BOOL inplace = SEC_FALSE);

Sec_Result cipherEncDecMult(TestCtx* ctx, SEC_OBJECTID id_pub, SEC_OBJECTID id_priv, Sec_CipherAlgorithm alg,
        const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace = SEC_FALSE);

Sec_Result testCipherUpdateIV(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherAlgorithm alg,
        Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace);

Sec_Result testProcessCtrWithDataShift(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherMode mode,
        SEC_BOOL inplace);

std::vector<SEC_BYTE> opensslAesEcb(TestKey key, Sec_CipherMode mode, bool padding, SEC_BYTE* iv,
        const std::vector<SEC_BYTE>& input);

std::vector<SEC_BYTE> opensslAesEcb(const std::vector<SEC_BYTE>& key, Sec_CipherMode mode, SEC_BOOL padding,
        SEC_BYTE* iv, const std::vector<SEC_BYTE>& input);

std::vector<SEC_BYTE> opensslAesGcm(const std::vector<SEC_BYTE>& key, Sec_CipherMode mode, SEC_BYTE* iv, SEC_BYTE* aad,
        SEC_SIZE aad_length, SEC_BYTE* tag, SEC_SIZE tag_length,
        const std::vector<SEC_BYTE>& input);

Sec_Result aesKeyCheck(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID id, SEC_BYTE* key, SEC_SIZE key_len);

Sec_Result testCtrRollover(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherMode mode,
        SEC_SIZE inputSize, SEC_BOOL inplace);

Sec_Result testProcessOpaqueWithMap(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, SEC_SIZE subsampleCount, SEC_SIZE bytesOfClearData);

Sec_Result testProcessOpaqueWithMapAndPattern(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg, SEC_SIZE subsampleCount, SEC_SIZE bytesOfClearData, SEC_SIZE numEncryptedBlocks,
        SEC_SIZE numClearBlocks);

Sec_Result testProcessOpaqueWithMapVariable(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm alg);

#endif // CIPHER_H
