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

#include "sec_adapter_utils.h"
#include <ctype.h>
#include <stdbool.h>

static const SEC_BYTE base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int is_base64(unsigned char c);

Sec_Result SecUtils_ReadFile(const char* path, void* data, SEC_SIZE data_len, SEC_SIZE* data_read) {
    FILE* f = NULL;
    SEC_BYTE last_byte;

    *data_read = 0;

    f = fopen(path, "rbe");
    if (f == NULL) {
        SEC_LOG_ERROR("Could not open file: %s", path);
        return SEC_RESULT_FAILURE;
    }

    while (ferror(f) == 0 && feof(f) == 0 && *data_read < data_len) {
        *data_read += fread(data, 1, data_len - *data_read, f);
    }

    if (ferror(f) != 0) {
        SEC_LOG_ERROR("Ferror encountered while reading file: %s", path);
        fclose(f);
        f = NULL;
        return SEC_RESULT_NO_SUCH_ITEM;
    }

    fread(&last_byte, 1, 1, f);

    if (feof(f) == 0) {
        SEC_LOG_ERROR("Data_len is too small");
        fclose(f);
        f = NULL;
        return SEC_RESULT_BUFFER_TOO_SMALL;
    }

    fclose(f);
    f = NULL;

    return SEC_RESULT_SUCCESS;
}

static long SecUtils_GetFileLen(const char* path) {
    FILE* f = NULL;
    long len = -1;

    f = fopen(path, "rbe");
    if (f == NULL) {
        SEC_LOG_ERROR("Could not open file: %s", path);
        return len;
    }

    fseek(f, 0L, SEEK_END);
    len = ftell(f);
    fseek(f, 0L, SEEK_SET);

    if (fclose(f) != 0) {
        SEC_LOG_ERROR("Fclose failed");
    }

    return len;
}

static Sec_Result SecUtils_VerifyFile(const char* path, void* expected, SEC_SIZE expected_len) {
    SEC_BYTE* read = NULL;
    SEC_SIZE read_len;
    SEC_SIZE file_len;

    //allocate memory for verification
    read = (SEC_BYTE*) malloc(expected_len);
    if (read == NULL) {
        SEC_LOG_ERROR("Malloc failed for file: %s", path);
        SEC_FREE(read);
        return SEC_RESULT_FAILURE;
    }

    //make sure that the written file is of proper length
    file_len = SecUtils_GetFileLen(path);
    if (expected_len != file_len) {
        SEC_LOG_ERROR("File written out (%s) is %d bytes, but expected %d", path, file_len, expected_len);
        SEC_FREE(read);
        return SEC_RESULT_FAILURE;
    }

    //read data back in
    if (SecUtils_ReadFile(path, read, expected_len, &read_len) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecUtils_ReadFile failed for file: %s", path);
        SEC_FREE(read);
        return SEC_RESULT_FAILURE;
    }

    //compare read data to input
    if (memcmp(expected, read, expected_len) != 0) {
        SEC_LOG_ERROR("Data read in does not match the data written out for file: %s", path);
        SEC_FREE(read);
        return SEC_RESULT_FAILURE;
    }

    SEC_FREE(read);
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_WriteFile(const char* path, void* data, SEC_SIZE data_len) {
    Sec_Result sec_res = SEC_RESULT_FAILURE;
    FILE* f = NULL;
    int fdesc;
    int dir_fdesc = -1;
    char* path_cpy = NULL;

    //make a copy of the path string since basedir will change it
    do {
        path_cpy = strdup(path);
        if (path_cpy == NULL) {
            SEC_LOG_ERROR("Strdup failed for file: %s", path);
            break;
        }

        //open file
        f = fopen(path, "wbe");
        if (f == NULL) {
            SEC_LOG_ERROR("Could not open file: %s, errno: %d", path, errno);
            break;
        }

        //get file descriptor
        fdesc = fileno(f);
        if (fdesc < 0) {
            SEC_LOG_ERROR("Fileno failed for file: %s, errno: %d", path, errno);
            break;
        }

        //write contents
        if (data_len != fwrite(data, 1, data_len, f)) {
            SEC_LOG_ERROR("Could not write to file: %s, errno: %d", path, errno);
            break;
        }

        //flush
        if (fflush(f) != 0) {
            SEC_LOG_ERROR("Fflush failed for file: %s, errno: %d", path, errno);
            break;
        }

        //force sync on written file
        if (fsync(fdesc) != 0) {
            SEC_LOG_ERROR("Fsync failed for file: %s, errno: %d", path, errno);
            break;
        }

        //close file
        if (fclose(f) != 0) {
            SEC_LOG_ERROR("Fclose failed for file: %s, errno: %d", path, errno);
            f = NULL;
            break;
        }
        f = NULL;

        //sync parent directory
        dir_fdesc = open(dirname(path_cpy), O_RDONLY | O_CLOEXEC); // NOLINT
        if (dir_fdesc < 0) {
            SEC_LOG_ERROR("Open parent failed for file: %s, errno: %d", path, errno);
            break;
        }

        if (fsync(dir_fdesc) != 0) {
            SEC_LOG_ERROR("Fsync parent failed for file: %s, errno: %d", path, errno);
            break;
        }

        if (close(dir_fdesc) != 0) {
            dir_fdesc = -1;
            SEC_LOG_ERROR("Close parent failed for file: %s, errno: %d", path, errno);
            break;
        }
        dir_fdesc = -1;

        //verify written file
        if (SecUtils_VerifyFile(path, data, data_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecUtils_VerifyFile failed for file: %s", path);
            break;
        }

        sec_res = SEC_RESULT_SUCCESS;
    } while (false);

    if (f != NULL) {
        if (fclose(f) != 0) {
            SEC_LOG_ERROR("Fclose failed for file: %s, errno: %d", path, errno);
        }
        f = NULL;
    }

    if (dir_fdesc >= 0) {
        if (close(dir_fdesc) != 0) {
            SEC_LOG_ERROR("Close parent failed for file: %s, errno: %d", path, errno);
        }
    }

    SEC_FREE(path_cpy);

    return sec_res;
}

Sec_Result SecUtils_RmFile(const char* path) {
    void* zeros = NULL;
    long len;

    len = SecUtils_GetFileLen(path);
    if (len > 0) {
        zeros = calloc(len, 1);
        if (zeros != NULL) {
            SecUtils_WriteFile(path, zeros, len);
            free(zeros);
        } else {
            SEC_LOG_ERROR("Calloc failed");
        }
    }

    if (unlink(path) != 0) {
        SEC_LOG_ERROR("Unlink %s failed", path);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

SEC_BOOL SecUtils_FileExists(const char* path) {
    FILE* f = NULL;

    f = fopen(path, "rbe");
    if (f == NULL)
        return SEC_FALSE;

    fclose(f);

    return SEC_TRUE;
}

SEC_SIZE SecUtils_LsDir(const char* path, Sec_LsDirEntry* entries, SEC_SIZE maxNumEntries) {
    struct dirent* dent;
    struct stat st;
    DIR* srcdir;
    SEC_SIZE found = 0;
    char file_path[SEC_MAX_FILE_PATH_LEN];

    srcdir = opendir(path);

    if (srcdir == NULL) {
        SEC_LOG_ERROR("Opendir failed");
        return 0;
    }

    while ((dent = readdir(srcdir)) != NULL) { // NOLINT
        snprintf(file_path, sizeof(file_path), "%s%s", path, dent->d_name);

        if (stat(file_path, &st) < 0) {
            SEC_LOG_ERROR("Fstatat failed on: %s", dent->d_name);
            continue;
        }

        /* store found file */
        if (entries != NULL && found < maxNumEntries) {
            snprintf(entries[found].name, sizeof(entries[found].name), "%s",
                    dent->d_name);
            entries[found].is_dir = S_ISDIR(st.st_mode);
        }

        ++found;
    }

    closedir(srcdir);
    return found;
}

Sec_Result SecUtils_MkDir(const char* path) {
    char tmp[SEC_MAX_FILE_PATH_LEN];
    char* p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0) {
        SEC_LOG_ERROR("Empty path string");
        return SEC_RESULT_FAILURE;
    }

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p != 0; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, S_IRWXU) != 0 && errno != EEXIST) {
                SEC_LOG_ERROR("Mkdir %s failed", tmp);
                return SEC_RESULT_FAILURE;
            }

            *p = '/';
        }
    }

    if (mkdir(tmp, S_IRWXU) != 0 && errno != EEXIST) {
        SEC_LOG_ERROR("Mkdir %s failed", tmp);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

SEC_SIZE SecUtils_UpdateItemList(SEC_OBJECTID* items, SEC_SIZE maxNumItems, SEC_SIZE numItems, SEC_OBJECTID item_id) {
    /* if array is full, just return it */
    if (numItems >= maxNumItems)
        return numItems;

    /* if item already in the list, skip it */
    if (SecUtils_ItemIndex(items, numItems, item_id) != -1)
        return numItems;

    items[numItems] = item_id;
    ++numItems;

    return numItems;
}

SEC_SIZE SecUtils_UpdateItemListFromDir(SEC_OBJECTID* items, SEC_SIZE maxNumItems, SEC_SIZE numItems, const char* dir,
        const char* ext) {
    SEC_SIZE numEntries;
    SEC_SIZE i;
    Sec_LsDirEntry entries[256];
    char pattern[256];
    SEC_OBJECTID item_id;

    snprintf(pattern, sizeof(pattern), "%s%s", SEC_OBJECTID_PATTERN, ext);

    numEntries = SecUtils_LsDir(dir, entries, 256);

    for (i = 0; i < numEntries; ++i) {
        if (!entries[i].is_dir && SecUtils_EndsWith(entries[i].name, ext)) {
            /* obtain 64-bit item id */
            if (sscanf(entries[i].name, pattern, &item_id) != 1) {
                SEC_LOG_ERROR("Sscanf failed on: %s", entries[i].name);
                continue;
            }

            numItems = SecUtils_UpdateItemList(items, maxNumItems, numItems, item_id);
        }
    }

    return numItems;
}

SEC_BYTE SecUtils_EndsWith(const char* str, const char* end) {
    SEC_SIZE lenstr;
    SEC_SIZE lenend;

    if (!str || !end)
        return 0;

    lenstr = strlen(str);
    lenend = strlen(end);
    if (lenend > lenstr)
        return 0;

    return strncmp(str + lenstr - lenend, end, lenend) == 0;
}

int SecUtils_ItemIndex(const SEC_OBJECTID* items, SEC_SIZE numItems, SEC_OBJECTID item) {
    int i;

    for (i = 0; i < numItems; ++i) {
        if (items[i] == item)
            return i;
    }

    return -1;
}

SEC_SIZE SecUtils_X509ToDerLen(X509* x509, void* mem, SEC_SIZE mem_len) {
    int written;
    SEC_BYTE* ptr = (SEC_BYTE*) mem;

    if (i2d_X509(x509, NULL) >= mem_len) {
        SEC_LOG_ERROR("Buffer is too small");
        return 0;
    }

    written = i2d_X509(x509, &ptr);

    if (written < 0) {
        SEC_LOG_ERROR("I2d_X509 failed");
        return 0;
    }

    return written;
}

EC_KEY* SecUtils_ECCFromDERPriv(const SEC_BYTE* der, SEC_SIZE der_len) {
    const unsigned char* p = (const unsigned char*) der;
    PKCS8_PRIV_KEY_INFO* p8 = NULL;
    EVP_PKEY* evp_key = NULL;
    EC_KEY* ecc = NULL;

    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, der_len);
    if (p8 != NULL) {
        evp_key = EVP_PKCS82PKEY(p8);
        if (evp_key == NULL) {
            SEC_LOG_ERROR("EVP_PKCS82PKEY failed");
            SEC_EVPPKEY_FREE(evp_key);
            PKCS8_PRIV_KEY_INFO_free(p8);
            return ecc;
        }
    } else {
        evp_key = d2i_AutoPrivateKey(NULL, &p, der_len);
        if (evp_key == NULL) {
            SEC_LOG_ERROR("d2i_AutoPrivateKey failed");
            SEC_EVPPKEY_FREE(evp_key);
            return ecc;
        }
    }

    ecc = EVP_PKEY_get1_EC_KEY(evp_key);
    if (ecc == NULL) {
        SEC_LOG_ERROR("EVP_PKEY_get1_EC_KEY failed");
        SEC_EVPPKEY_FREE(evp_key);
        if (p8 != NULL)
            PKCS8_PRIV_KEY_INFO_free(p8);

        return ecc;
    }

    SEC_EVPPKEY_FREE(evp_key);
    if (p8 != NULL)
        PKCS8_PRIV_KEY_INFO_free(p8);

    return ecc;
}

Sec_Result SecUtils_ECCToPubBinary(EC_KEY* ec_key, Sec_ECCRawPublicKey* binary) {
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;

    if (SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, NULL) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecUtils_ECCToPubBinary: SecUtils_Extract_EC_KEY_X_Y failed");
        return SEC_RESULT_FAILURE;
    }

    binary->type = SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
    Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(binary->type), binary->key_len);
    SecUtils_BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
    SecUtils_BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

    BN_free(y);
    BN_free(x);
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_Base64Encode(const SEC_BYTE* input, SEC_SIZE input_len, SEC_BYTE* output, SEC_SIZE max_output,
        SEC_SIZE* out_len) {
    int i = 0;
    int j;
    SEC_BYTE arr3[3];
    SEC_BYTE arr4[4];
    SEC_SIZE ret_len = 0;

    *out_len = 0;
    memset(arr3, 0, 3);
    memset(arr4, 0, 4);
    while (input_len--) {
        arr3[i++] = *(input++);
        if (i == 3) {
            arr4[0] = (arr3[0] & 0xfc) >> 2;
            arr4[1] = ((arr3[0] & 0x03) << 4) + ((arr3[1] & 0xf0) >> 4);
            arr4[2] = ((arr3[1] & 0x0f) << 2) + ((arr3[2] & 0xc0) >> 6);
            arr4[3] = arr3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                if (ret_len >= max_output) {
                    SEC_LOG_ERROR("Output buffer too small");
                    return SEC_RESULT_FAILURE;
                }

                output[ret_len++] = base64_chars[arr4[i]];
            }

            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            arr3[j] = '\0';
        }

        arr4[0] = (arr3[0] & 0xfc) >> 2;
        arr4[1] = ((arr3[0] & 0x03) << 4) + ((arr3[1] & 0xf0) >> 4);
        arr4[2] = ((arr3[1] & 0x0f) << 2) + ((arr3[2] & 0xc0) >> 6);
        arr4[3] = arr3[2] & 0x3f;

        for (j = 0; j < (i + 1); j++) {
            if (ret_len >= max_output) {
                SEC_LOG_ERROR("Output buffer too small");
                return SEC_RESULT_FAILURE;
            }

            output[ret_len++] = base64_chars[arr4[j]];
        }

        while (i++ < 3) {
            if (ret_len >= max_output) {
                SEC_LOG_ERROR("Output buffer too small");
                return SEC_RESULT_FAILURE;
            }

            output[ret_len++] = '=';
        }
    }

    *out_len = ret_len;
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_Base64Decode(const SEC_BYTE* input, SEC_SIZE in_len, SEC_BYTE* output, SEC_SIZE max_output,
        SEC_SIZE* out_len) {
    Sec_Result status = SEC_RESULT_FAILURE;
    SEC_SIZE i = 0;
    SEC_SIZE j = 0;
    SEC_SIZE z = 0;
    SEC_SIZE ret_len = 0;
    SEC_SIZE curPos = 0;
    SEC_BYTE arr3[3];
    SEC_BYTE arr4[4];

    *out_len = 0;

    if (in_len <= 1) {
        SEC_LOG_ERROR("Illegal base64 string");
        return SEC_RESULT_FAILURE;
    }

    memset(arr3, 0, 3);
    memset(arr4, 0, 4);
    while (in_len-- && (input[curPos] != '=') && is_base64(input[curPos])) {
        arr4[i++] = input[curPos];
        curPos++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                for (z = 0; z < 64; z++) {
                    if (base64_chars[z] == arr4[i]) {
                        arr4[i] = (SEC_BYTE) z;
                        break;
                    }
                }
            }

            arr3[0] = (arr4[0] << 2) + ((arr4[1] & 0x30) >> 4);
            arr3[1] = ((arr4[1] & 0xf) << 4) + ((arr4[2] & 0x3c) >> 2);
            arr3[2] = ((arr4[2] & 0x3) << 6) + arr4[3];

            for (i = 0; i < 3; i++) {
                if (ret_len >= max_output) {
                    SEC_LOG_ERROR("Output buffer too small");
                    return SEC_RESULT_FAILURE;
                }
                output[ret_len++] = arr3[i];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) {
            arr4[j] = 0;
        }

        for (j = 0; j < 4; j++) {
            for (z = 0; z < 64; z++) {
                if (base64_chars[z] == arr4[j]) {
                    arr4[j] = z;
                    break;
                }
            }
        }

        arr3[0] = (arr4[0] << 2) + ((arr4[1] & 0x30) >> 4);
        arr3[1] = ((arr4[1] & 0xf) << 4) + ((arr4[2] & 0x3c) >> 2);
        arr3[2] = ((arr4[2] & 0x3) << 6) + arr4[3];

        for (j = 0; (j < i - 1); j++) {
            if (ret_len >= max_output) {
                SEC_LOG_ERROR("Output buffer too small");
                return SEC_RESULT_FAILURE;
            }
            output[ret_len++] = arr3[j];
        }
    }

    if (0 == ret_len ) return SEC_RESULT_FAILURE;
    *out_len = ret_len;
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_ECCToPrivBinary(EC_KEY* ec_key, Sec_ECCRawPrivateKey* binary) {
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    Sec_KeyType keyType;

    if (SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, &keyType) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecUtils_ECCToPrivBinary: SecUtils_Extract_EC_KEY_X_Y failed");
        return SEC_RESULT_FAILURE;
    }

    if (keyType != SEC_KEYTYPE_ECC_NISTP256_PUBLIC) {
        SEC_LOG_ERROR("Unexpected key type encountered: %d", keyType);
        return SEC_RESULT_FAILURE;
    }

    binary->type = SEC_KEYTYPE_ECC_NISTP256;
    Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(keyType), binary->key_len);
    SecUtils_BigNumToBuffer((BIGNUM*) EC_KEY_get0_private_key(ec_key), binary->prv,
            Sec_BEBytesToUint32(binary->key_len));
    SecUtils_BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
    SecUtils_BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

    BN_free(y);
    BN_free(x);
    return SEC_RESULT_SUCCESS;
}

RSA* SecUtils_RSAFromDERPriv(const SEC_BYTE* der, SEC_SIZE der_len) {
    const unsigned char* p = (const unsigned char*) der;
    PKCS8_PRIV_KEY_INFO* p8 = NULL;
    EVP_PKEY* evp_key = NULL;
    RSA* rsa = NULL;

    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, der_len);
    if (p8 != NULL) {
        evp_key = EVP_PKCS82PKEY(p8);
        if (evp_key == NULL) {
            SEC_LOG_ERROR("EVP_PKCS82PKEY failed");
            SEC_EVPPKEY_FREE(evp_key);
            PKCS8_PRIV_KEY_INFO_free(p8);
            return rsa;
        }
    } else {
        evp_key = d2i_AutoPrivateKey(NULL, &p, der_len);
        if (evp_key == NULL) {
            SEC_LOG_ERROR("d2i_AutoPrivateKey failed");
            SEC_EVPPKEY_FREE(evp_key);
            return rsa;
        }
    }

    rsa = EVP_PKEY_get1_RSA(evp_key);
    if (rsa == NULL) {
        SEC_LOG_ERROR("EVP_PKEY_get1_RSA failed");
        SEC_EVPPKEY_FREE(evp_key);
        if (p8 != NULL)
            PKCS8_PRIV_KEY_INFO_free(p8);

        return rsa;
    }

    SEC_EVPPKEY_FREE(evp_key);
    if (p8 != NULL)
        PKCS8_PRIV_KEY_INFO_free(p8);

    return rsa;
}

Sec_Result SecUtils_RSAToDERPrivKeyInfo(RSA* rsa, SEC_BYTE* output, SEC_SIZE out_len, SEC_SIZE* written) {
    BIO* bio = NULL;
    EVP_PKEY* evp_key = NULL;
    BUF_MEM* bptr = NULL;

    evp_key = EVP_PKEY_new();
    if (EVP_PKEY_set1_RSA(evp_key, rsa) == 0) {
        SEC_LOG_ERROR("EVP_PKEY_set1_RSA failed");
        SEC_EVPPKEY_FREE(evp_key);
        SEC_BIO_FREE(bio);
        return SEC_RESULT_FAILURE;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        SEC_LOG_ERROR("BIO_new(BIO_s_mem()) failed");
        SEC_EVPPKEY_FREE(evp_key);
        SEC_BIO_FREE(bio);
        return SEC_RESULT_FAILURE;
    }

    if (!i2d_PKCS8PrivateKeyInfo_bio(bio, evp_key)) {
        SEC_LOG_ERROR("I2d_PKCS8_PRIV_KEY_INFO_bio failed");
        SEC_EVPPKEY_FREE(evp_key);
        SEC_BIO_FREE(bio);
        return SEC_RESULT_FAILURE;
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    *written = bptr->length;

    if (output != NULL) {
        if (out_len < bptr->length) {
            SEC_LOG_ERROR("Output buffer is not large enough");
            SEC_EVPPKEY_FREE(evp_key);
            SEC_BIO_FREE(bio);
            return SEC_RESULT_FAILURE;
        }

        memcpy(output, bptr->data, bptr->length);
    }

    SEC_EVPPKEY_FREE(evp_key);
    SEC_BIO_FREE(bio);
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_WrapSymetric(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID wrappingKey,
        Sec_CipherAlgorithm wrappingAlg, SEC_BYTE* iv, SEC_BYTE* payload, SEC_SIZE payloadLen, SEC_BYTE* out,
        SEC_SIZE out_len, SEC_SIZE* written) {
    if (SecCipher_SingleInputId(processorHandle, wrappingAlg, SEC_CIPHERMODE_ENCRYPT, wrappingKey, iv, payload,
                payloadLen, out, out_len, written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_BigNumToBuffer(const BIGNUM* bignum, SEC_BYTE* buffer, SEC_SIZE buffer_len) {
    SEC_SIZE num_bytes;

    memset(buffer, 0, buffer_len);
    num_bytes = BN_num_bytes(bignum);

    if (num_bytes > buffer_len) {
        SEC_LOG_ERROR("Buffer not large enough.  needed: %d, actual: %d", num_bytes, buffer_len);
        return SEC_RESULT_FAILURE;
    }

    BN_bn2bin(bignum, buffer + buffer_len - num_bytes);
    return SEC_RESULT_SUCCESS;
}

/*
 * The next steps a caller might take are:
 * SecUtils_BigNumToBuffer(x, public_key->x, Sec_BEBytesToUint32(public_key->key_len));
 * SecUtils_BigNumToBuffer(y, public_key->y, Sec_BEBytesToUint32(public_key->key_len));
 */
Sec_Result SecUtils_Extract_EC_KEY_X_Y(const EC_KEY* ec_key, BIGNUM** xp, BIGNUM** yp, Sec_KeyType* keyTypep) {
    const EC_GROUP* group = NULL;
    const EC_POINT* ec_point = NULL;
    BN_CTX* ctx = NULL;

    if (xp == NULL) {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: X cannot be NULL");
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return SEC_RESULT_FAILURE;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_group: %s", ERR_error_string(ERR_get_error(), NULL));
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return SEC_RESULT_FAILURE;
    }

    ec_point = EC_KEY_get0_public_key(ec_key);
    if (ec_point == NULL) {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_public_key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return SEC_RESULT_FAILURE;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        SEC_LOG_ERROR("BN_CTX_new() failed");
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return SEC_RESULT_FAILURE;
    }

    *xp = BN_new();
    if (*xp == NULL) {
        SEC_LOG_ERROR("BN_new() failed");
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return SEC_RESULT_FAILURE;
    }

    if (yp != NULL) { // if caller wants y coordinate returned
        *yp = BN_new();
        if (*yp == NULL) {
            SEC_LOG_ERROR("BN_new() failed");
            if (ctx != NULL)
                BN_CTX_free(ctx);

            return SEC_RESULT_FAILURE;
        }
    }

    if (keyTypep != NULL) // if caller wants key type returned
    {
        *keyTypep = SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
    }

    // Get the X coordinate and optionally the Y coordinate
    if (EC_POINT_get_affine_coordinates_GFp(group, ec_point, *xp, yp != NULL ? *yp : NULL, ctx) != 1) {
        BN_clear_free(*xp);
        if (yp != NULL)
            BN_clear_free(*yp);
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_POINT_get_affine_coordinates_GFp: %s",
                ERR_error_string(ERR_get_error(), NULL));
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return SEC_RESULT_FAILURE;
    }

    if (ctx != NULL)
        BN_CTX_free(ctx);

    return SEC_RESULT_SUCCESS;
}

// ec_key is the other side's public ECC key
//
// Returns the number of bytes in the encrypted output or
// -1 if there was an error
int SecUtils_ElGamal_Encrypt_Rand(EC_KEY* ec_key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* output,
        SEC_SIZE outputSize, BIGNUM* sender_rand) {
    int result = -1;
    BIGNUM* inputAsBN = NULL;
    const EC_GROUP* group = NULL;
    const EC_POINT* P = NULL;
    const EC_POINT* PK_recipient = NULL;
    EC_POINT* shared_secret = NULL;
    EC_POINT* key_2_wrap_point = NULL;
    EC_POINT* sender_share = NULL;
    EC_POINT* wrapped_key = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    BN_CTX* ctx = NULL;

    do {
        if (inputSize != SEC_ECC_NISTP256_KEY_LEN) {
            SEC_LOG_ERROR("Input size needed != One BIGNUM");
            break;
        }

        if (outputSize < 4 * SEC_ECC_NISTP256_KEY_LEN) {
            SEC_LOG_ERROR("Output size needed < Four BIGNUMs");
            break;
        }

        // Convert the input buffer to be encrypted to a BIGNUM
        inputAsBN = BN_new();
        if (inputAsBN == NULL) {
            SEC_LOG_ERROR("BN_new failed");
            break;
        }
        if (BN_bin2bn(input, (int) inputSize, inputAsBN) == NULL) {
            SEC_LOG_ERROR("BN_bin2bn failed. Error: %s",
                    ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        group = EC_KEY_get0_group(ec_key);
        if (group == NULL) {
            SEC_LOG_ERROR("EC_KEY_get0_group failed");
            break;
        }

        ctx = BN_CTX_new();
        if (ctx == NULL) {
            SEC_LOG_ERROR("BN_CTX_new failed");
            break;
        }

        // Convert the X coordinate to an EC Point.  This takes the desired Y value in 1 bit (to choose
        // which of the two possible Y values to use).  This *calculates* an actual Y value for the point.
        key_2_wrap_point = EC_POINT_new(group);
        if (key_2_wrap_point == NULL) {
            SEC_LOG_ERROR("EC_POINT_new failed");
            break;
        }

        if (!EC_POINT_set_compressed_coordinates_GFp(group, key_2_wrap_point, inputAsBN, 0, ctx)) //$$$ 1=>0 on 7/8/15
        {
            // Don't print an error message if the error is "point not on curve" 100A906E, but still fail
            if (ERR_get_error() != 0x100A906E) // i.e. error:100A906E:lib(16):func(169):reason(110)
                SEC_LOG_ERROR("Set EC_POINT_set_compressed_coordinates_GFp failed. Error: %s",
                        ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        // Calc sender's shared point 'wP' => this gets sent back to receiver
        sender_share = EC_POINT_new(group);
        if (sender_share == NULL) {
            SEC_LOG_ERROR("EC_POINT_new failed");
            break;
        }

        P = EC_GROUP_get0_generator(group);
        if (P == NULL) {
            SEC_LOG_ERROR("EC_GROUP_get0_generator failed");
            break;
        }

        EC_POINT_mul(group, sender_share, NULL, P, sender_rand, ctx);

        // Calc sender's Shared Secret 'wRr'  => this hides the key I want to send
        shared_secret = EC_POINT_new(group);
        if (shared_secret == NULL) {
            SEC_LOG_ERROR("EC_POINT_new failed");
            break;
        }

        PK_recipient = EC_KEY_get0_public_key(ec_key);
        if (PK_recipient == NULL) {
            SEC_LOG_ERROR("EC_KEY_get0_public_key failed");
            break;
        }

        EC_POINT_mul(group, shared_secret, NULL, PK_recipient, sender_rand, ctx);

        // key_2_wrap_point is a point on the curve, we add the shared_secret
        // to it and send the result, the wrapped_key, to the receiver.
        wrapped_key = EC_POINT_new(group);
        if (wrapped_key == NULL) {
            SEC_LOG_ERROR("EC_POINT_new failed");
            break;
        }

        EC_POINT_add(group, wrapped_key, key_2_wrap_point, shared_secret, ctx);

        // Dissect the wrapped point to get its coordinates
        x = BN_new();
        if (x == NULL) {
            SEC_LOG_ERROR("BN_new failed");
            break;
        }

        y = BN_new();
        if (y == NULL) {
            SEC_LOG_ERROR("BN_new failed");
            break;
        }

        // Dissect shared_secret to get its coordinates and output them
        EC_POINT_get_affine_coordinates_GFp(group, sender_share, x, y, ctx);
        if (SecUtils_BigNumToBuffer(x, (unsigned char*) &output[0 * SEC_ECC_NISTP256_KEY_LEN],
                    SEC_ECC_NISTP256_KEY_LEN) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
            break;
        }

        if (SecUtils_BigNumToBuffer(y, (unsigned char*) &output[1 * SEC_ECC_NISTP256_KEY_LEN],
                    SEC_ECC_NISTP256_KEY_LEN) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
            break;
        }

        // Dissect wrapped_key to get its coordinates and output them
        EC_POINT_get_affine_coordinates_GFp(group, wrapped_key, x, y, ctx);

        if (SecUtils_BigNumToBuffer(x, (unsigned char*) &output[2 * SEC_ECC_NISTP256_KEY_LEN],
                    SEC_ECC_NISTP256_KEY_LEN) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
            break;
        }

        if (SecUtils_BigNumToBuffer(y, (unsigned char*) &output[3 * SEC_ECC_NISTP256_KEY_LEN],
                    SEC_ECC_NISTP256_KEY_LEN) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
            break;
        }

        result = 4 * SEC_ECC_NISTP256_KEY_LEN;
    } while (false);

    if (x != NULL)
        BN_free(x);
    if (y != NULL)
        BN_free(y);
    if (inputAsBN != NULL)
        BN_free(inputAsBN);
    if (sender_rand != NULL)
        BN_free(sender_rand);
    if (shared_secret != NULL)
        EC_POINT_free(shared_secret);
    if (sender_share != NULL)
        EC_POINT_free(sender_share);
    if (key_2_wrap_point != NULL)
        EC_POINT_free(key_2_wrap_point);
    if (wrapped_key != NULL)
        EC_POINT_free(wrapped_key);
    BN_CTX_free(ctx);
    return result;
}

// ec_key is the other side's public ECC key
//
// Returns the number of bytes in the encrypted output or
// -1 if there was an error
int SecUtils_ElGamal_Encrypt(EC_KEY* ec_key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* output,
        SEC_SIZE outputSize) {
    // Generate random number 'w' (multiplier) for the sender
    BIGNUM* sender_rand = BN_new();

    if (sender_rand == NULL) {
        SEC_LOG_ERROR("BN_new failed");
        return -1;
    }

    if (BN_rand(sender_rand, 256, -1, 0) == 0) {
        SEC_LOG_ERROR("BN_rand failed");
        if (sender_rand != NULL)
            BN_free(sender_rand);
        return -1;
    }

    return SecUtils_ElGamal_Encrypt_Rand(ec_key, input, inputSize, output, outputSize, sender_rand);
}

EC_KEY* SecUtils_ECCFromPubBinary(Sec_ECCRawPublicKey* binary) {
    BN_CTX* ctx = BN_CTX_new();

    if (binary->type != SEC_KEYTYPE_ECC_NISTP256_PUBLIC && binary->type != SEC_KEYTYPE_ECC_NISTP256)
        return NULL;

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM* xp;
    BIGNUM* yp;

    if (((xp = BN_CTX_get(ctx)) == NULL) || ((yp = BN_CTX_get(ctx)) == NULL)) {
        EC_POINT_free(ec_point);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return ec_key;
    }

    EC_POINT_set_affine_coordinates_GFp(group, ec_point,
            BN_bin2bn(binary->x, (int) Sec_BEBytesToUint32(binary->key_len), xp),
            BN_bin2bn(binary->y, (int) Sec_BEBytesToUint32(binary->key_len), yp), ctx);
    EC_KEY_set_public_key(ec_key, ec_point);

    EC_POINT_free(ec_point);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ec_key;
}

Sec_Result SecUtils_FillKeyStoreUserHeader(Sec_ProcessorHandle* processorHandle, SecUtils_KeyStoreHeader* header,
        Sec_KeyContainer container) {
    Sec_Memset(header, 0, sizeof(SecUtils_KeyStoreHeader));

    if (SecProcessor_GetDeviceId(processorHandle, header->device_id) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecProcessor_GetDeviceId failed");
        return SEC_RESULT_FAILURE;
    }

    header->inner_kc_type = container;
    return SEC_RESULT_SUCCESS;
}

SecUtils_KeyStoreHeader* SecUtils_GetKeyStoreUserHeader(void* store) {
    return (SecUtils_KeyStoreHeader*) SecStore_GetUserHeader(store);
}

Sec_Result SecUtils_ValidateKeyStore(Sec_ProcessorHandle* processorHandle, SEC_BOOL require_mac, void* store,
        SEC_SIZE store_len) {
    SecUtils_KeyStoreHeader header;
    SEC_BYTE device_id[SEC_DEVICEID_LEN];

    Sec_Memset(&header, 0, sizeof(header));

    if (store_len < sizeof(SecStore_Header) || store_len < SecStore_GetStoreLen(store)) {
        SEC_LOG_ERROR("Invalid store");
        return SEC_RESULT_FAILURE;
    }

    if (memcmp(SEC_UTILS_KEYSTORE_MAGIC, SecStore_GetHeader(store)->user_header_magic,
                strlen(SEC_UTILS_KEYSTORE_MAGIC)) != 0) {
        SEC_LOG_ERROR("Invalid key store magic value");
        return SEC_RESULT_FAILURE;
    }

    if (SecStore_RetrieveData(processorHandle, require_mac, &header, sizeof(header), NULL, 0, store, store_len) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecStore_RetrieveData failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecProcessor_GetDeviceId(processorHandle, device_id) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecProcessor_GetDeviceId failed");
        return SEC_RESULT_FAILURE;
    }

    if (memcmp(device_id, header.device_id, SEC_DEVICEID_LEN) != 0) {
        SEC_LOG_ERROR("Device_id does not match the key store");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result write_verification_file(Sec_ProcessorHandle* processorHandle, char* filename, SEC_BYTE* data,
        SEC_SIZE data_length, SEC_BYTE* info, size_t info_length) {
    SEC_BYTE digest[SHA256_DIGEST_LENGTH * 2];
    SEC_SIZE length = 0;

    if (SecDigest_SingleInput(processorHandle, SEC_DIGESTALGORITHM_SHA256, data, data_length, digest,
                &length) != SEC_RESULT_SUCCESS ||
            length != SHA256_DIGEST_LENGTH) {
        SEC_LOG_ERROR("Unable to calculate verification digest");
        return SEC_RESULT_FAILURE;
    }

    if (info != NULL) {
        if (SecDigest_SingleInput(processorHandle, SEC_DIGESTALGORITHM_SHA256, info, info_length,
                    digest + SHA256_DIGEST_LENGTH, &length) != SEC_RESULT_SUCCESS ||
                length != SHA256_DIGEST_LENGTH) {
            SEC_LOG_ERROR("Unable to calculate verification digest");
            return SEC_RESULT_FAILURE;
        }
    } else {
        memset(digest + SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);
    }

    if (SecUtils_WriteFile(filename, digest, SHA256_DIGEST_LENGTH * 2) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Could not write verification file");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result verify_verification_file(Sec_ProcessorHandle* processorHandle, char* filename, SEC_BYTE* data,
        SEC_SIZE data_length, SEC_BYTE* info, size_t info_length) {
    SEC_BYTE digest[SHA256_DIGEST_LENGTH * 2];
    SEC_SIZE length;
    if (SecUtils_ReadFile(filename, digest, sizeof(digest), &length) != SEC_RESULT_SUCCESS ||
            length != sizeof(digest)) {
        SEC_LOG_ERROR("Could not read verification file");
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    SEC_BYTE digest_result[SHA256_DIGEST_LENGTH];
    if (SecDigest_SingleInput(processorHandle, SEC_DIGESTALGORITHM_SHA256, data, data_length, digest_result,
                &length) != SEC_RESULT_SUCCESS ||
            length != SHA256_DIGEST_LENGTH) {
        SEC_LOG_ERROR("Unable to calculate verification digest");
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    if (memcmp(digest_result, digest, SHA256_DIGEST_LENGTH) != 0) {
        SEC_LOG_ERROR("verification mismatch on data file");
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    if (info != NULL) {
        if (SecDigest_SingleInput(processorHandle, SEC_DIGESTALGORITHM_SHA256, info, info_length,
                    digest_result, &length) != SEC_RESULT_SUCCESS ||
                length != SHA256_DIGEST_LENGTH) {
            SEC_LOG_ERROR("Unable to calculate verification digest");
            return SEC_RESULT_VERIFICATION_FAILED;
        }

        if (memcmp(digest_result, digest + SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH) != 0) {
            SEC_LOG_ERROR("verification mismatch on info file");
            return SEC_RESULT_VERIFICATION_FAILED;
        }
    }

    return SEC_RESULT_SUCCESS;
}

static int is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}
