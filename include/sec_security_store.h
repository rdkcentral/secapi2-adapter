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

#ifndef SEC_SECURITY_STORE_H_
#define SEC_SECURITY_STORE_H_

#include "sec_adapter_processor.h"
#include "sec_adapter_pubops.h"

#ifdef __cplusplus
#include <cstdlib>
#include <cstring>
extern "C" {
#else
#include <stdlib.h>
#include <string.h>
#endif

/**
 *            Secure store structure
 *
 *           |----------------------|---------
 *           |          | Mandatory | Signed
 *           | Header   |-----------|
 *           |          | User def  |
 * ----------|----------------------|
 * Encrypted | Data                 |
 *           |----------------------|
 *           | Padding              |
 *           |----------------------|---------
 *           | Mac                  |
 * ----------|----------------------|
 *           | IV                   |
 *           |----------------------|
 */

#define SEC_STORE_FLAG_IS_ENCRYPTED 0x01
#define SEC_STORE_FLAG_IS_MACED 0x02
#define SEC_STORE_MAC_LEN 32
#define SEC_STORE_IV_LEN 16
#define SEC_STORE_MAGIC "SECSTOR1"

#define SEC_STORE_AES_LADDER_INPUT "securestore" \
                                   "encryption" \
                                   "aes128" \
                                   "vendor128"
#define SEC_STORE_MAC_LADDER_INPUT "securestore" \
                                   "mackeygen" \
                                   "aes128" \
                                   "vendor128"

#define SEC_STORE_USERHEADERMAGIC_LEN 4

typedef struct {
    /* fixed value 'SECSTOR' + ver */
    uint8_t store_magic[8];

    /* header length - including user defined */
    uint8_t header_len[4];

    /* data length (without padding) */
    uint8_t data_len[4];

    /* user header magic */
    uint8_t user_header_magic[SEC_STORE_USERHEADERMAGIC_LEN];

    /* reserved */
    uint8_t reserved[3];

    /* flags */
    uint8_t flags;
} SecStore_Header;

Sec_Result SecStore_GenerateLadderInputs(Sec_ProcessorHandle* processorHandle, const char* input, const char* input2,
        SEC_BYTE* output, SEC_SIZE len);

SecStore_Header* SecStore_GetHeader(void* store);

void* SecStore_GetUserHeader(void* store);

SEC_SIZE SecStore_GetStoreLen(void* store);

SEC_SIZE SecStore_GetUserHeaderLen(void* store);

SEC_SIZE SecStore_GetDataLen(void* store);

SEC_SIZE SecStore_CalculateRequiredStoreLen(SEC_SIZE user_header_len, SEC_SIZE data_len);

Sec_Result SecStore_RetrieveData(Sec_ProcessorHandle* proc, SEC_BOOL require_mac, void* user_header,
        SEC_SIZE user_header_len, void* data, SEC_SIZE data_len, void* store, SEC_SIZE storeLen);

Sec_Result SecStore_RetrieveDataWithKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID aesKeyId,
        SEC_OBJECTID macGenId, SEC_BOOL require_mac, void* user_header, SEC_SIZE user_header_len, void* data,
        SEC_SIZE data_len, void* store, SEC_SIZE storeLen);

Sec_Result SecStore_StoreData(Sec_ProcessorHandle* proc, SEC_BOOL encrypt, SEC_BOOL gen_mac,
        SEC_BYTE* user_header_magic, void* user_header, SEC_SIZE user_header_len, void* data, SEC_SIZE data_len,
        void* store, SEC_SIZE storeLen);

Sec_Result SecStore_StoreDataWithKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID aesKeyId, SEC_OBJECTID macGenId,
        SEC_BOOL encrypt, SEC_BOOL gen_mac, SEC_BYTE* user_header_magic, void* user_header, SEC_SIZE user_header_len,
        void* data, SEC_SIZE data_len, void* store, SEC_SIZE storeLen);

SEC_SIZE SecStore_GetHeaderLen(void* store);

#ifdef __cplusplus
}
#endif

#endif // SEC_SECURITY_STORE_H_
