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

#ifndef SEC_SECURITY_UTILS_H_
#define SEC_SECURITY_UTILS_H_

#include "sec_security.h"
#include "sec_security_store.h"
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sys/stat.h>

#ifdef __cplusplus
#include <cerrno>
#include <cstring>
extern "C" {
#else
#include <errno.h>
#include <string.h>
#endif

#define SEC_INVALID_EPOCH ((SEC_SIZE) -1)

typedef struct {
    uint8_t inner_kc_type;
    uint8_t reserved[7];
    uint8_t device_id[SEC_DEVICEID_LEN];
} SecUtils_KeyStoreHeader;

#define SEC_UTILS_KEYSTORE_MAGIC "KST0"

/**
 * @brief Read data from a file into a specified buffer.
 *
 * @param path file path
 * @param data output data buffer where the file contents will be written
 * @param data_len length of the output buffer
 * @param data_read actual number of bytes written
 *
 * @return status of the operation
 */
Sec_Result SecUtils_ReadFile(const char* path, void* data, SEC_SIZE data_len, SEC_SIZE* data_read);

/**
 * @brief Write the input data into a specified file.
 *
 * @param path output file path
 * @param data data to write
 * @param data_len length of input data
 *
 * @return status of the operation
 */
Sec_Result SecUtils_WriteFile(const char* path, void* data, SEC_SIZE data_len);

/**
 * @brief create a specified directory.
 * @param path directory path
 */
Sec_Result SecUtils_MkDir(const char* path);

/**
 * @brief Remove a specified file.
 *
 * @param path of the file to remove
 */
Sec_Result SecUtils_RmFile(const char* path);

/**
 * @brief Checks whether the specified file exists.
 *
 * @param path file path
 *
 * @return 1 if the file exists, 0 if it does not
 */
SEC_BOOL SecUtils_FileExists(const char* path);

typedef struct {
    char name[SEC_MAX_FILE_PATH_LEN];
    SEC_BYTE is_dir;
} Sec_LsDirEntry;

/**
 * @brief Obtain directory entries from a specified dir.
 *
 * @param path path of the directory to list
 * @param entries pointer to the entry array.  If NULL, the entries info will not be filled in, but the number
 * of items will still be returned
 * @param maxNumEntries The maximum number of entries to fill.
 *
 * @return number of directory entries in a specified dir
 */
SEC_SIZE SecUtils_LsDir(const char* path, Sec_LsDirEntry* entries, SEC_SIZE maxNumEntries);

/**
 * @brief Checks whether the specified strings ends with the other string.
 */
SEC_BYTE SecUtils_EndsWith(const char* str, const char* end);

/**
 * @brief obtain the index of the item in a list.
 */
int SecUtils_ItemIndex(const SEC_OBJECTID* items, SEC_SIZE numItems, SEC_OBJECTID item);

/**
 * @brief insert new item into the list if it does not exist.
 */
SEC_SIZE SecUtils_UpdateItemList(SEC_OBJECTID* items, SEC_SIZE maxNumItems, SEC_SIZE numItems, SEC_OBJECTID item_id);

/**
 * @brief insert new items into the list from the specified directory.
 */
SEC_SIZE SecUtils_UpdateItemListFromDir(SEC_OBJECTID* items, SEC_SIZE maxNumItems, SEC_SIZE numItems, const char* dir,
        const char* ext);

SEC_SIZE SecUtils_X509ToDerLen(X509* x509, void* mem, SEC_SIZE mem_len);

/**
 * @brief Convert the given epoch to iso formatted string.
 */
char* SecUtils_Epoch2IsoTime(SEC_SIZE epoch, char* iso_time, SEC_SIZE iso_time_size);

/**
 * @brief Convert the given iso time string to epoch value.
 */
SEC_SIZE SecUtils_IsoTime2Epoch(const char* iso_time);

EC_KEY* SecUtils_ECCFromDERPriv(const SEC_BYTE* der, SEC_SIZE der_len);

Sec_Result SecUtils_ECCToPubBinary(EC_KEY* ec_key, Sec_ECCRawPublicKey* binary);

/**
 * @brief Base64 encode the input string.
 */
Sec_Result SecUtils_Base64Encode(const SEC_BYTE* input, SEC_SIZE input_len, SEC_BYTE* output, SEC_SIZE max_output,
        SEC_SIZE* out_len);

/**
 * @brief base64 decode the input string.
 */
Sec_Result SecUtils_Base64Decode(const SEC_BYTE* input, SEC_SIZE in_len, SEC_BYTE* output, SEC_SIZE max_output,
        SEC_SIZE* out_len);

/**
 * @brief Write OpenSSL EC_KEY object into a private key binary blob
 *
 * The private key also contains the public key
 */
Sec_Result SecUtils_ECCToPrivBinary(EC_KEY* ec_key, Sec_ECCRawPrivateKey* binary);

Sec_Result SecUtils_ECCToDERPrivKeyInfo(EC_KEY* ec_key, SEC_BYTE* output, SEC_SIZE out_len, SEC_SIZE* written);

RSA* SecUtils_RSAFromDERPriv(const SEC_BYTE* der, SEC_SIZE der_len);

Sec_Result SecUtils_RSAToDERPrivKeyInfo(RSA* rsa, SEC_BYTE* output, SEC_SIZE out_len, SEC_SIZE* written);

Sec_Result SecUtils_WrapSymmetric(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID wrappingKey,
        Sec_CipherAlgorithm wrappingAlg, SEC_BYTE* iv, SEC_BYTE* payload, SEC_SIZE payloadLen, SEC_BYTE* out,
        SEC_SIZE out_len, SEC_SIZE* written);

Sec_Result SecUtils_BigNumToBuffer(const BIGNUM* bignum, SEC_BYTE* buffer, SEC_SIZE buffer_len);

Sec_Result SecUtils_Extract_EC_KEY_X_Y(const EC_KEY* ec_key, BIGNUM** xp, BIGNUM** yp, Sec_KeyType* keyTypep);

int SecUtils_ElGamal_Encrypt_Rand(EC_KEY* ec_key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* output,
        SEC_SIZE outputSize, BIGNUM* sender_rand);

int SecUtils_ElGamal_Encrypt(EC_KEY* ec_key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* output,
        SEC_SIZE outputSize);

EC_KEY* SecUtils_ECCFromPubBinary(Sec_ECCRawPublicKey* binary);

Sec_Result SecUtils_FillKeyStoreUserHeader(Sec_ProcessorHandle* processorHandle, SecUtils_KeyStoreHeader* header,
        Sec_KeyContainer container);

SecUtils_KeyStoreHeader* SecUtils_GetKeyStoreUserHeader(void* store);

Sec_Result SecUtils_ValidateKeyStore(Sec_ProcessorHandle* processorHandle, SEC_BOOL require_mac, void* store,
        SEC_SIZE store_len);

Sec_Result write_verification_file(Sec_ProcessorHandle* processorHandle, char* filename, SEC_BYTE* data,
        SEC_SIZE data_length, SEC_BYTE* info, size_t info_length);

Sec_Result verify_verification_file(Sec_ProcessorHandle* processorHandle, char* filename, SEC_BYTE* data,
        SEC_SIZE data_length, SEC_BYTE* info, size_t info_length);

#ifdef __cplusplus
}
#endif

#endif // SEC_SECURITY_UTILS_H_
