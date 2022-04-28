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

#ifndef MAC_H
#define MAC_H

#include "sec_security.h"
#include "test_creds.h"
#include <vector>

Sec_Result testMacOverKey(Sec_MacAlgorithm alg, SEC_OBJECTID id_mac, TestKey keyMac, TestKc kc, SEC_OBJECTID id_payload,
        TestKey keyPayload, Sec_StorageLoc loc);

Sec_Result testMacSingle(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_MacAlgorithm alg,
        SEC_SIZE inputSize);

Sec_Result testMacMult(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_MacAlgorithm alg,
        const std::vector<SEC_SIZE>& inputSizes);

std::vector<SEC_BYTE> macOpenSSL(Sec_MacAlgorithm alg, TestKey key, const std::vector<SEC_BYTE>& input);

Sec_Result macCheck(Sec_ProcessorHandle* processorHandle, Sec_MacAlgorithm alg, SEC_OBJECTID id, SEC_BYTE* key,
        SEC_SIZE key_len);

#endif // MAC_H
