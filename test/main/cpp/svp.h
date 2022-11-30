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

#ifndef SVP_H
#define SVP_H

#include "sec_security.h"
#include "test_creds.h"
#include <vector>

Sec_Result testOpaqueMalloc();

Sec_Result testCopyOpaque();

Sec_Result testSecureBootEnabled();

Sec_Result testSetTime();

Sec_Result testKeycheckOpaque(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc);

Sec_Result testProcessOpaque(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm cipher_algorithm, int size);

Sec_Result testProcessDataShiftOpaque(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc);

Sec_Result testOpaqueMultiProcHandle(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
        Sec_CipherAlgorithm cipher_algorithm, int size);

#endif // SVP_H
