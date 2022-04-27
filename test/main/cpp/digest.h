/**
 * Copyright 2020 Comcast Cable Communications Management, LLC
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

#ifndef DIGEST_H
#define DIGEST_H

#include "sec_security.h"
#include "test_creds.h"
#include <vector>

Sec_Result testDigestSingle(Sec_DigestAlgorithm alg, SEC_SIZE inputSize);

Sec_Result testDigestMult(Sec_DigestAlgorithm alg, const std::vector<SEC_SIZE>& inputSizes);

Sec_Result testDigestOverKey(Sec_DigestAlgorithm alg, SEC_OBJECTID id, TestKey key, Sec_StorageLoc loc);

std::vector<SEC_BYTE> digestOpenSSL(Sec_DigestAlgorithm alg, const std::vector<SEC_BYTE>& input);

#endif // DIGEST_H
