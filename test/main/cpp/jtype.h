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

#ifndef JTYPE_H
#define JTYPE_H

#include "sec_security.h"
#include "test_creds.h"
#include <string>

Sec_Result testProvisionJType(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc,
        int version, const char* valg);

Sec_Result testDecryptJType(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc,
        Sec_CipherAlgorithm alg, SEC_SIZE input_len, int version, const char* calg);

Sec_Result testExportKey(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc,
        Sec_CipherAlgorithm alg, SEC_SIZE input_len, int version, const char* calg);

std::string createJTypeContainer(const char* kid, const char* macalg, TestKey contentKey, TestKey encryptionKey,
        const char* contentKeyId, const char* contentKeyRights, SEC_BOOL cacheable, int contentKeyUsage,
        const char* contentKeyNotBefore, const char* contentKeyNotOnOrAfter, TestKey macKey, int version,
        const char* alg);

std::string createDefaultRights(Sec_KeyType kt);

#endif // JTYPE_H
