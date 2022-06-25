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

#include "sec_security_store.h"
#include <stdbool.h>

#define SEC_STORE_MAC_KEY_INPUT "securestore" \
                                "integrity" \
                                "hmacSha256" \
                                "aes128ecb" \
                                "decrypt"

Sec_Result SecStore_GenerateLadderInputs(Sec_ProcessorHandle* processorHandle, const char* input, const char* input2,
        SEC_BYTE* output, SEC_SIZE len) {
    Sec_Buffer sec_buf;
    SEC_BYTE sec_buf_mem[256];
    SEC_BYTE digest[SEC_DIGEST_MAX_LEN];
    SEC_SIZE digest_len;
    SEC_SIZE to_copy;
    SEC_SIZE loop = 1;
    SEC_BYTE loop_buf[4];
    CHECK_PROCHANDLE(processorHandle)

    SecBuffer_Init(&sec_buf, sec_buf_mem, sizeof(sec_buf_mem));

    while (len > 0) {
        SecBuffer_Reset(&sec_buf);

        Sec_Uint32ToBEBytes(loop, loop_buf);

        if (input != NULL && SEC_RESULT_SUCCESS != SecBuffer_Write(&sec_buf, (SEC_BYTE*) input, strlen(input))) {
            SEC_LOG_ERROR("SecBuffer_Write failed");
            return SEC_RESULT_FAILURE;
        }

        if (input2 != NULL && SEC_RESULT_SUCCESS != SecBuffer_Write(&sec_buf, (SEC_BYTE*) input2, strlen(input2))) {
            SEC_LOG_ERROR("SecBuffer_Write failed");
            return SEC_RESULT_FAILURE;
        }

        if (SecBuffer_Write(&sec_buf, loop_buf, sizeof(loop_buf)) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecBuffer_Write failed");
            return SEC_RESULT_FAILURE;
        }

        if (SecDigest_SingleInput(processorHandle, SEC_DIGESTALGORITHM_SHA256, sec_buf.base, sec_buf.written, digest,
                    &digest_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecDigest_SingleInput failed");
            return SEC_RESULT_FAILURE;
        }

        to_copy = SEC_MIN(digest_len, len);
        memcpy(output, digest, to_copy);
        len -= to_copy;
        output += to_copy;

        ++loop;
    }

    return SEC_RESULT_SUCCESS;
}

static SEC_SIZE SecStore_CalculatePaddedDataLen(SEC_SIZE dataLen) {
    return dataLen + SEC_AES_BLOCK_SIZE - (dataLen % SEC_AES_BLOCK_SIZE);
}

SecStore_Header* SecStore_GetHeader(void* store) {
    return (SecStore_Header*) store;
}

void* SecStore_GetUserHeader(void* store) {
    return (SEC_BYTE*) store + sizeof(SecStore_Header);
}

SEC_SIZE SecStore_GetHeaderLen(void* store) {
    return Sec_BEBytesToUint32(SecStore_GetHeader(store)->header_len);
}

SEC_SIZE SecStore_GetDataLen(void* store) {
    return Sec_BEBytesToUint32(SecStore_GetHeader(store)->data_len);
}

static SEC_SIZE SecStore_GetPaddedDataLen(void* store) {
    return SecStore_CalculatePaddedDataLen(SecStore_GetDataLen(store));
}

static SEC_SIZE SecStore_CalculateStoreLen(SEC_SIZE header_len, SEC_SIZE data_len) {
    return header_len + SecStore_CalculatePaddedDataLen(data_len) + SEC_STORE_MAC_LEN + SEC_STORE_IV_LEN;
}

SEC_SIZE SecStore_CalculateRequiredStoreLen(SEC_SIZE user_header_len, SEC_SIZE data_len) {
    return sizeof(SecStore_Header) + user_header_len + SecStore_CalculatePaddedDataLen(data_len) + SEC_STORE_MAC_LEN +
           SEC_STORE_IV_LEN;
}

SEC_SIZE SecStore_GetStoreLen(void* store) {
    return SecStore_CalculateStoreLen(SecStore_GetHeaderLen(store), SecStore_GetDataLen(store));
}

SEC_SIZE SecStore_GetUserHeaderLen(void* store) {
    return SecStore_GetHeaderLen(store) - sizeof(SecStore_Header);
}

static SEC_BYTE* SecStore_GetMac(void* store) {
    return ((SEC_BYTE*) store) + SecStore_GetStoreLen(store) - SEC_STORE_IV_LEN - SEC_STORE_MAC_LEN;
}

static SEC_BYTE* SecStore_GetIV(void* store) {
    return ((SEC_BYTE*) store) + SecStore_GetStoreLen(store) - SEC_STORE_IV_LEN;
}

static SEC_BYTE* SecStore_GetData(void* store) {
    return ((SEC_BYTE*) store) + SecStore_GetHeaderLen(store);
}

static Sec_Result SecStore_ComputeMacKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID keyId, const char* input,
        SEC_BYTE* key, SEC_SIZE key_len) {
    SEC_SIZE digest_len;
    SEC_SIZE written;

    if (SecDigest_GetDigestLenForAlgorithm(SEC_DIGESTALGORITHM_SHA256) != key_len) {
        SEC_LOG_ERROR("Unexpected key_len: %d", key_len);
        return SEC_RESULT_FAILURE;
    }

    if (SecDigest_SingleInput(processorHandle, SEC_DIGESTALGORITHM_SHA256, (SEC_BYTE*) input, strlen(input), key,
                &digest_len) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecDigest_SingleInput failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecCipher_SingleInputId(processorHandle, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, keyId,
                NULL, key, key_len, key, key_len, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result SecStore_Encrypt(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID keyId, void* store,
        SEC_SIZE storeLen) {
    SEC_SIZE expected_enc_data_len;
    SEC_SIZE written;

    if (store == NULL) {
        SEC_LOG_ERROR("Null store");
        return SEC_RESULT_FAILURE;
    }

    if (storeLen < sizeof(SecStore_Header) || storeLen < SecStore_GetStoreLen(store)) {
        SEC_LOG_ERROR("Invalid store length: %d", storeLen);
        return SEC_RESULT_FAILURE;
    }

    if (!(SEC_STORE_FLAG_IS_ENCRYPTED & SecStore_GetHeader(store)->flags)) {
        SEC_LOG_ERROR("Encryption flag is not set");
        return SEC_RESULT_FAILURE;
    }

    if (SecRandom_SingleInput(processorHandle, SEC_RANDOMALGORITHM_TRUE, SecStore_GetIV(store), SEC_STORE_IV_LEN) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecRandom_SingleInput failed");
        return SEC_RESULT_FAILURE;
    }

    expected_enc_data_len = SecStore_GetPaddedDataLen(store) + SEC_STORE_MAC_LEN;

    if (SecCipher_SingleInputId(processorHandle, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, keyId,
                SecStore_GetIV(store), SecStore_GetData(store), expected_enc_data_len, SecStore_GetData(store),
                expected_enc_data_len, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    if (written != expected_enc_data_len) {
        SEC_LOG_ERROR("Unexpected number of encrypted bytes written");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result SecStore_Decrypt(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID keyId, void* store,
        SEC_SIZE storeLen) {
    SEC_SIZE expected_enc_data_len;
    SEC_SIZE written;

    if (store == NULL) {
        SEC_LOG_ERROR("Null store");
        return SEC_RESULT_FAILURE;
    }

    if (storeLen < sizeof(SecStore_Header) || storeLen < SecStore_GetStoreLen(store)) {
        SEC_LOG_ERROR("Invalid store length: %d", storeLen);
        return SEC_RESULT_FAILURE;
    }

    if (!(SEC_STORE_FLAG_IS_ENCRYPTED & SecStore_GetHeader(store)->flags)) {
        SEC_LOG_ERROR("This store is not encrypted");
        return SEC_RESULT_FAILURE;
    }

    expected_enc_data_len = SecStore_GetPaddedDataLen(store) + SEC_STORE_MAC_LEN;

    if (SecCipher_SingleInputId(processorHandle, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_DECRYPT, keyId,
                SecStore_GetIV(store), SecStore_GetData(store), expected_enc_data_len, SecStore_GetData(store),
                expected_enc_data_len, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    if (written != expected_enc_data_len) {
        SEC_LOG_ERROR("Unexpected number of decrypted bytes written");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecStore_RetrieveData(Sec_ProcessorHandle* processorHandle, SEC_BOOL require_mac, void* user_header,
        SEC_SIZE user_header_len, void* data, SEC_SIZE data_len, void* store, SEC_SIZE storeLen) {
    Sec_Result result;

    result = SecStore_RetrieveDataWithKey(processorHandle, SEC_OBJECTID_STORE_AES_KEY, SEC_OBJECTID_STORE_MACKEYGEN_KEY,
            require_mac, user_header, user_header_len, data, data_len, store, storeLen);

    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecStore_RetrieveDataWithKey failed");
    }

    return result;
}

Sec_Result SecStore_RetrieveDataWithKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID aesKeyId,
        SEC_OBJECTID macGenId, SEC_BOOL require_mac, void* user_header, SEC_SIZE user_header_len, void* data,
        SEC_SIZE data_len, void* store, SEC_SIZE storeLen) {
    Sec_Result result = SEC_RESULT_FAILURE;
    SEC_BYTE mac_key[SEC_STORE_MAC_LEN];
    SEC_BYTE mac[SEC_STORE_MAC_LEN];
    void* copy = NULL;
    SEC_BYTE pad[SEC_AES_BLOCK_SIZE];
    CHECK_PROCHANDLE(processorHandle)

    do {
        if (store == NULL) {
            SEC_LOG_ERROR("Null store");
            break;
        }

        if (storeLen < sizeof(SecStore_Header)) {
            SEC_LOG_ERROR("Invalid store length: %d", storeLen);
            break;
        }

        if (memcmp(SEC_STORE_MAGIC, SecStore_GetHeader(store)->store_magic, strlen(SEC_STORE_MAGIC)) != 0) {
            SEC_LOG_ERROR("Invalid store magic value");
            break;
        }

        if (storeLen < SecStore_GetStoreLen(store)) {
            SEC_LOG_ERROR("Invalid store length: %d", storeLen);
            break;
        }

        /* create a copy of the store that will be decrypted */
        copy = malloc(SecStore_GetStoreLen(store));
        if (copy == NULL) {
            SEC_LOG_ERROR("Malloc failed");
            break;
        }
        memcpy(copy, store, SecStore_GetStoreLen(store));

        /* decrypt container */
        if (SecStore_GetHeader(copy)->flags & SEC_STORE_FLAG_IS_ENCRYPTED) {
            if (SecStore_Decrypt(processorHandle, aesKeyId, copy, SecStore_GetStoreLen(copy)) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecStore_Decrypt failed");
                break;
            }
        }

        /* check padding */
        memset(pad, (int) (SecStore_GetPaddedDataLen(copy) - SecStore_GetDataLen(copy)), sizeof(pad));
        if (Sec_Memcmp(pad, SecStore_GetData(copy) + SecStore_GetDataLen(copy), pad[0]) != 0) {
            SEC_LOG_ERROR("Invalid pad value encountered");
            break;
        }

        /* mac value */
        if (!(SecStore_GetHeader(copy)->flags & SEC_STORE_FLAG_IS_MACED)) {
            if (require_mac) {
                SEC_LOG_ERROR("Key container does not have a mac value");
                break;
            }
        } else {
            if (SecStore_ComputeMacKey(processorHandle, macGenId, SEC_STORE_MAC_KEY_INPUT, mac_key, sizeof(mac_key)) !=
                    SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecStore_ComputeMacKey failed");
                break;
            }

            result = Pubops_HMAC(SEC_MACALGORITHM_HMAC_SHA256, mac_key, sizeof(mac_key), copy,
                    SecStore_GetStoreLen(copy) - SEC_STORE_MAC_LEN - SEC_STORE_IV_LEN, mac, SEC_STORE_MAC_LEN);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("Pubops_HMAC failed");
                Sec_Memset(mac_key, 0, sizeof(mac_key));
                return SEC_RESULT_FAILURE;
            }

            Sec_Memset(mac_key, 0, sizeof(mac_key));
            if (Sec_Memcmp(mac, SecStore_GetMac(copy), SEC_STORE_MAC_LEN) != 0) {
                SEC_LOG_ERROR("Mac does not match");
                break;
            }
        }

        /* get user_header */
        if (user_header != NULL) {
            if (user_header_len < SecStore_GetUserHeaderLen(copy)) {
                SEC_LOG_ERROR("Output buffer not large enough to hold user_header");
                break;
            }

            memcpy(user_header, SecStore_GetUserHeader(copy), SecStore_GetUserHeaderLen(copy));
        }

        /* get data */
        if (data != NULL) {
            if (data_len < SecStore_GetDataLen(copy)) {
                SEC_LOG_ERROR("Output buffer not large enough to hold data");
                break;
            }

            memcpy(data, SecStore_GetData(copy), SecStore_GetDataLen(copy));
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    Sec_Memset(mac_key, 0, sizeof(mac_key));
    if (copy != NULL) {
        Sec_Memset(copy, 0, SecStore_GetStoreLen(store));
        SEC_FREE(copy);
    }

    return result;
}

Sec_Result SecStore_StoreData(Sec_ProcessorHandle* processorHandle, SEC_BOOL encrypt, SEC_BOOL gen_mac,
        SEC_BYTE* user_header_magic, void* user_header, SEC_SIZE user_header_len, void* data, SEC_SIZE data_len,
        void* store, SEC_SIZE storeLen) {
    Sec_Result result;

    result = SecStore_StoreDataWithKey(processorHandle, SEC_OBJECTID_STORE_AES_KEY, SEC_OBJECTID_STORE_MACKEYGEN_KEY,
            encrypt, gen_mac, user_header_magic, user_header, user_header_len, data, data_len, store, storeLen);

    if (result != SEC_RESULT_SUCCESS)
        SEC_LOG_ERROR("SecStore_StoreDataWithKey failed");

    return result;
}

Sec_Result SecStore_StoreDataWithKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID aesKeyId, SEC_OBJECTID macGenId,
        SEC_BOOL encrypt, SEC_BOOL gen_mac, SEC_BYTE* user_header_magic, void* user_header, SEC_SIZE user_header_len,
        void* data, SEC_SIZE data_len, void* store, SEC_SIZE storeLen) {
    SecStore_Header* header = NULL;
    SEC_BYTE mac_key[SEC_STORE_MAC_LEN];
    SEC_BYTE pad;
    CHECK_PROCHANDLE(processorHandle)

    if (store == NULL) {
        SEC_LOG_ERROR("Null store");
        return SEC_RESULT_FAILURE;
    }

    if (storeLen < SecStore_CalculateStoreLen(sizeof(SecStore_Header) + user_header_len, data_len)) {
        SEC_LOG_ERROR("Invalid store length: %d", storeLen);
        return SEC_RESULT_FAILURE;
    }

    header = (SecStore_Header*) store;

    /* fill header */
    memset(header, 0, sizeof(SecStore_Header));
    memcpy(header->store_magic, SEC_STORE_MAGIC, strlen(SEC_STORE_MAGIC));
    if (gen_mac)
        header->flags |= SEC_STORE_FLAG_IS_MACED;

    if (encrypt)
        header->flags |= SEC_STORE_FLAG_IS_ENCRYPTED;

    Sec_Uint32ToBEBytes(data_len, header->data_len);
    Sec_Uint32ToBEBytes(sizeof(SecStore_Header) + user_header_len, header->header_len);
    if (user_header_magic != NULL)
        memcpy(header->user_header_magic, user_header_magic, sizeof(header->user_header_magic));

    /* store user header */
    memcpy(SecStore_GetUserHeader(store), user_header, user_header_len);

    /* store data */
    memcpy(SecStore_GetData(store), data, data_len);

    /* pad data */
    pad = SecStore_GetPaddedDataLen(store) - SecStore_GetDataLen(store);
    memset(SecStore_GetData(store) + data_len, pad, pad);

    if (gen_mac) {
        /* calc mac */
        if (SecStore_ComputeMacKey(processorHandle, macGenId, SEC_STORE_MAC_KEY_INPUT, mac_key, sizeof(mac_key)) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecStore_ComputeMacKey failed");
            return SEC_RESULT_FAILURE;
        }

        if (Pubops_HMAC(SEC_MACALGORITHM_HMAC_SHA256, mac_key, sizeof(mac_key), store,
                    SecStore_GetStoreLen(store) - SEC_STORE_MAC_LEN - SEC_STORE_IV_LEN, SecStore_GetMac(store),
                    SEC_STORE_MAC_LEN) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Pubops_HMAC failed");
            Sec_Memset(mac_key, 0, sizeof(mac_key));
            return SEC_RESULT_FAILURE;
        }

        Sec_Memset(mac_key, 0, sizeof(mac_key));
    }

    if (encrypt && SEC_RESULT_SUCCESS != SecStore_Encrypt(processorHandle, aesKeyId, store, storeLen)) {
        SEC_LOG_ERROR("SecStore_Encrypt failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}
