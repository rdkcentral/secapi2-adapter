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

#ifndef KEY_H
#define KEY_H

#include "sec_security.h"
#include "test_creds.h"

Sec_Result testStore(SEC_BOOL encrypt, SEC_BOOL mac);

Sec_Result testStoreProvision(SEC_OBJECTID id, SEC_BOOL encrypt, SEC_BOOL mac);

Sec_Result testKeyProvision(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc);

Sec_Result testKeyProvisionDouble(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, TestKey key2, TestKc kc2,
        Sec_StorageLoc loc2);

Sec_Result testKeyGetKeyInfo(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc);

Sec_Result testKeyNoSha(SEC_OBJECTID id, TestKey key, TestKc kc);

Sec_Result testKeyExtractPublicKey(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc);

Sec_Result testKeyGenerate(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc, bool testEncDec);

Sec_Result testKeyDeriveHKDF(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc, Sec_MacAlgorithm macAlgorithm,
        bool testEncDec, bool useSalt);

Sec_Result testKeyDeriveConcatKDF(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc,
        Sec_DigestAlgorithm digestAlgorithm, bool testEncDec);

Sec_Result testKeyDeriveVendorAes128(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc,
        Sec_MacAlgorithm macAlgorithm, bool testEncDec);

Sec_Result testKeyDeriveKeyLadderAes128(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc,
        Sec_KeyLadderRoot root, bool testEncDec);

Sec_Result testKeyComputeBaseKeyDigest(SEC_OBJECTID id, Sec_DigestAlgorithm alg);

Sec_Result testKeyECDHKeyAgreementWithKDF(SEC_OBJECTID id_derived, SEC_OBJECTID id_priv, TestKey priv, TestKc priv_kc,
        TestKey pub, Sec_KeyType keyType, Sec_StorageLoc loc, Sec_DigestAlgorithm digestAlgorithm, bool testEncDec);

Sec_Result testKeyDeriveCMACAES128(SEC_OBJECTID idDerived, SEC_OBJECTID idBase, TestKc baseKc, Sec_KeyType keyType,
        Sec_StorageLoc loc, bool testEncDec, SEC_BYTE counter, uint32_t L);

Sec_Result testKeyDeriveBaseKey(SEC_OBJECTID idDerived, Sec_StorageLoc loc);

Sec_Result testKeyDeriveHKDFBaseKey(Sec_KeyType typeDerived, Sec_StorageLoc loc, Sec_MacAlgorithm macAlgorithm);

Sec_Result testKeyDeriveConcatKDFBaseKey(Sec_KeyType typeDerived, Sec_StorageLoc loc,
        Sec_DigestAlgorithm digestAlgorithm);

Sec_Result testExportProvisionedKey(TestKey key, TestKc kc);

#endif // KEY_H
