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

#ifndef SEC_ADAPTER_PUBOPS_H
#define SEC_ADAPTER_PUBOPS_H

#include "sec_security.h"
#include <memory.h>
#include <openssl/cmac.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

Sec_Result Pubops_VerifyX509WithPubEcc(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey* pub);

Sec_Result Pubops_ExtractRSAPubFromX509Der(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_RSARawPublicKey* pub);

Sec_Result Pubops_ExtractECCPubFromX509Der(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey* pub);

Sec_Result Pubops_VerifyX509WithPubRsa(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_RSARawPublicKey* pub);

Sec_Result Pubops_ExtractRSAPubFromPUBKEYDer(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_RSARawPublicKey* pub);

Sec_Result Pubops_ExtractECCPubFromPUBKEYDer(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey* pub);

Sec_Result Pubops_ExtractECCPubToPUBKEYDer(Sec_ECCRawPublicKey* eccRawPublicKey, SEC_BYTE** out, SEC_SIZE* outLength);

Sec_Result Pubops_VerifyWithPubRsa(RSA* rsa, Sec_SignatureAlgorithm alg, SEC_BYTE* digest, SEC_SIZE digest_len,
        SEC_BYTE* sig, SEC_SIZE sig_len, int salt_len);

Sec_Result Pubops_VerifyWithPubEcc(EC_KEY* ec_key, Sec_SignatureAlgorithm alg, SEC_BYTE* digest, SEC_SIZE digest_len,
        SEC_BYTE* sig, SEC_SIZE sig_len);

Sec_Result Pubops_HMAC(Sec_MacAlgorithm alg, SEC_BYTE* key, SEC_SIZE key_len, SEC_BYTE* input, SEC_SIZE input_len,
        SEC_BYTE* mac, SEC_SIZE mac_len);

#endif // SEC_ADAPTER_PUBOPS_H
