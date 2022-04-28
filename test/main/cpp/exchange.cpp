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

#include "exchange.h" // NOLINT
#include "cipher.h"
#include "mac.h"
#include "sec_adapter_utils.h"
#include "test_ctx.h"

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/kdf.h>
#endif

// Some of the values here are derived from RFC 3526 which is
// Copyright (C) The Internet Society (2003).  All Rights Reserved.
static SEC_BYTE g_dh_p[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
        0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
        0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
        0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
        0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
        0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
        0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
        0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
        0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
        0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
        0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
        0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
        0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
        0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
        0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
        0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
        0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
        0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
        0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
        0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
        0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d,
        0x04, 0x50, 0x7a, 0x33, 0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64,
        0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a, 0x8a, 0xea, 0x71, 0x57,
        0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
        0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0,
        0x4a, 0x25, 0x61, 0x9d, 0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b,
        0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64, 0xd8, 0x76, 0x02, 0x73,
        0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
        0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0,
        0xba, 0xd9, 0x46, 0xe2, 0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31,
        0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e, 0x4b, 0x82, 0xd1, 0x20,
        0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static SEC_BYTE g_dh_g[] = {
        0x02,
};

static EC_KEY* ECCFromPubBinary(Sec_ECCRawPublicKey* binary) {
    BN_CTX* ctx = BN_CTX_new();

    if (binary->type != SEC_KEYTYPE_ECC_NISTP256_PUBLIC && binary->type != SEC_KEYTYPE_ECC_NISTP256)
        return nullptr;

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM* xp;
    BIGNUM* yp;
    do {
        if (((xp = BN_CTX_get(ctx)) == nullptr) || ((yp = BN_CTX_get(ctx)) == nullptr))
            break;

        EC_POINT_set_affine_coordinates_GFp(group, ec_point,
                BN_bin2bn(binary->x, static_cast<int>(Sec_BEBytesToUint32(binary->key_len)), xp),
                BN_bin2bn(binary->y, static_cast<int>(Sec_BEBytesToUint32(binary->key_len)), yp), ctx);
        EC_KEY_set_public_key(ec_key, ec_point);
    } while (false);

    EC_POINT_free(ec_point);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ec_key;
}

static Sec_KeyType GroupToKeyType(const EC_GROUP* group) {
    if (nullptr == group)
        return SEC_KEYTYPE_NUM;
    switch (EC_GROUP_get_curve_name(group)) {
        case NID_X9_62_prime256v1:
            return SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
        case 0:
        default:
            return SEC_KEYTYPE_NUM;
    }
}

static Sec_Result BigNumToBuffer(const BIGNUM* bignum, SEC_BYTE* buffer, SEC_SIZE buffer_len) {
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

static Sec_Result Extract_EC_KEY_X_Y(const EC_KEY* ec_key, BIGNUM** xp, BIGNUM** yp, Sec_KeyType* keyTypep) {
    const EC_GROUP* group;
    const EC_POINT* ec_point;
    BN_CTX* ctx = nullptr;
    Sec_Result result = SEC_RESULT_FAILURE;

    do {
        if (xp == nullptr) {
            SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: X cannot be NULL");
            break;
        }

        group = EC_KEY_get0_group(ec_key);
        if (group == nullptr) {
            SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_group: %s",
                    ERR_error_string(ERR_get_error(), nullptr));
            break;
        }

        ec_point = EC_KEY_get0_public_key(ec_key);
        if (ec_point == nullptr) {
            SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_public_key: %s",
                    ERR_error_string(ERR_get_error(), nullptr));
            break;
        }

        ctx = BN_CTX_new();
        if (ctx == nullptr) {
            SEC_LOG_ERROR("BN_CTX_new() failed");
            break;
        }

        *xp = BN_new();
        if (*xp == nullptr) {
            SEC_LOG_ERROR("BN_new() failed");
            break;
        }

        if (nullptr != yp) { // if caller wants y coordinate returned
            *yp = BN_new();
            if (*yp == nullptr) {
                SEC_LOG_ERROR("BN_new() failed");
                break;
            }
        }

        if (nullptr != keyTypep) { // if caller wants key type returned
            *keyTypep = GroupToKeyType(group);
        }

        // Get the X coordinate and optionally the Y coordinate
        if (EC_POINT_get_affine_coordinates_GFp(group, ec_point, *xp, yp != nullptr ? *yp : nullptr, ctx) != 1) {
            BN_clear_free(*xp);
            if (nullptr != yp)
                BN_clear_free(*yp);

            SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_POINT_get_affine_coordinates_GFp: %s",
                    ERR_error_string(ERR_get_error(), nullptr));
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (nullptr != ctx)
        BN_CTX_free(ctx);

    return result;
}

static Sec_Result ECCToPubBinary(EC_KEY* ec_key, Sec_ECCRawPublicKey* binary) {
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;
    Sec_KeyType keyType;

    if (Extract_EC_KEY_X_Y(ec_key, &x, &y, &keyType) != SEC_RESULT_SUCCESS) {

        SEC_LOG_ERROR("_Extract_EC_KEY_X_Y failed");
        return SEC_RESULT_FAILURE;
    }

    binary->type = keyType;
    Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(keyType), binary->key_len);
    BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
    BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

    BN_free(y);
    BN_free(x);
    return SEC_RESULT_SUCCESS;
}

static DH* DH_create(SEC_BYTE* p, SEC_SIZE p_len, SEC_BYTE* g, SEC_SIZE g_len) {
    DH* dh;

    if ((dh = DH_new()) == nullptr) {
        SEC_LOG_ERROR("DH_new failed");
        return nullptr;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = BN_bin2bn(p, static_cast<int>(p_len), nullptr);
    dh->g = BN_bin2bn(g, static_cast<int>(g_len), nullptr);

    if ((dh->p == nullptr) || (dh->g == nullptr)) {
        SEC_LOG_ERROR("BN_bin2bn failed");
        DH_free(dh);
        return nullptr;
    }

    dh->length = static_cast<int64_t>(p_len) * 8L;
#else
    BIGNUM* bnp = BN_bin2bn(p, static_cast<int>(p_len), nullptr);
    BIGNUM* bng = BN_bin2bn(g, static_cast<int>(g_len), nullptr);
    DH_set0_pqg(dh, bnp, nullptr, bng);
#endif

    return dh;
}

static Sec_Result DH_generate_key(DH* dh, SEC_BYTE* publicKey, SEC_SIZE pubKeySize, SEC_SIZE* out_len) {
    if (DH_generate_key(dh) == 0) {
        SEC_LOG_ERROR("DH_generate_key failed");
        DH_free(dh);
        return SEC_RESULT_FAILURE;
    }

    SEC_SIZE modulus_size = DH_size(dh);
    if (pubKeySize < modulus_size) {
        SEC_LOG_ERROR("Buffer to small");
        return SEC_RESULT_FAILURE;
    }


#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int temp_len = BN_bn2bin(dh->pub_key, publicKey);
#else
    const BIGNUM* pub_key = nullptr;
    DH_get0_key(dh, &pub_key, nullptr);

    int temp_len = BN_bn2bin(pub_key, publicKey);
#endif
    if (temp_len <= 0) {
        SEC_LOG_ERROR("DH_compute_key failed");
        return SEC_RESULT_FAILURE;
    }

    if (temp_len < modulus_size) {
        memmove(publicKey + modulus_size - temp_len, publicKey, temp_len);
        memset(publicKey, 0, modulus_size - temp_len);
    }

    *out_len = modulus_size;
    return SEC_RESULT_SUCCESS;
}

static Sec_Result DH_compute(DH* dh, SEC_BYTE* pub_key, SEC_SIZE pub_key_len, SEC_BYTE* key, SEC_SIZE key_len,
        SEC_SIZE* written) {
    SEC_SIZE modulus_size = DH_size(dh);
    if (key_len < modulus_size) {
        SEC_LOG_ERROR("Key_len is not large enough to hold the computed DH key: %d", DH_size(dh));
        return SEC_RESULT_FAILURE;
    }

    BIGNUM* pub_key_bn = BN_bin2bn(pub_key, static_cast<int>(pub_key_len), nullptr);
    if (pub_key_bn == nullptr) {
        SEC_LOG_ERROR("BN_bin2bn failed");
        return SEC_RESULT_FAILURE;
    }

    int temp_len = DH_compute_key(key, pub_key_bn, dh);
    BN_free(pub_key_bn);

    if (temp_len <= 0) {
        SEC_LOG_ERROR("DH_compute_key failed");
        return SEC_RESULT_FAILURE;
    }

    if (temp_len < modulus_size) {
        memmove(key + modulus_size - temp_len, key, temp_len);
        memset(key, 0, modulus_size - temp_len);
    }

    *written = modulus_size;
    return SEC_RESULT_SUCCESS;
}

static Sec_Result hkdf(SEC_BYTE* key, SEC_SIZE key_len, SEC_BYTE* out, const SEC_SIZE* out_len, bool use_salt) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* Extract */
    const EVP_MD* evp_md = EVP_sha256();

    SEC_BYTE prk[SEC_MAC_MAX_LEN];
    SEC_SIZE prk_len;

    if (HMAC(evp_md, use_salt ? "salt" : "", use_salt ? 4 : 0, key, key_len, prk, &prk_len) == nullptr) {
        SEC_LOG_ERROR("HMAC failed");
        return SEC_RESULT_FAILURE;
    }

    /* Expand */
    size_t digest_length = SHA256_DIGEST_LENGTH;
    size_t r = *out_len / digest_length + ((*out_len % digest_length == 0) ? 0 : 1);
    SEC_BYTE t[SEC_MAC_MAX_LEN];
    unsigned int t_len = 0;

    Sec_Result result = SEC_RESULT_SUCCESS;
    for (size_t i = 1; i <= r; i++) {
        SEC_BYTE loop = i;
        SEC_SIZE cp_len;

        if (i == r) {
            SEC_SIZE mod = *out_len % digest_length;
            cp_len = (mod == 0) ? digest_length : mod;
        } else {
            cp_len = digest_length;
        }

        HMAC_CTX _ctx;
        HMAC_CTX* ctx = &_ctx;
        HMAC_CTX_init(ctx);
        if (HMAC_Init_ex(ctx, prk, static_cast<int>(prk_len), evp_md, nullptr) != OPENSSL_SUCCESS) {
            SEC_LOG_ERROR("HMAC_Init_ex failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        if (t_len > 0 && OPENSSL_SUCCESS != HMAC_Update(ctx, t, t_len)) {
            SEC_LOG_ERROR("HMAC_Update failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        if (HMAC_Update(ctx, (unsigned char*) "label", 5) != OPENSSL_SUCCESS) { // NOLINT
            SEC_LOG_ERROR("HMAC_Update failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        if (HMAC_Update(ctx, &loop, 1) != OPENSSL_SUCCESS) {
            SEC_LOG_ERROR("HMAC_Update failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        if (HMAC_Final(ctx, t, &t_len) != OPENSSL_SUCCESS) {
            SEC_LOG_ERROR("HMAC_Final failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        HMAC_CTX_cleanup(ctx);

        memcpy(out + (i - 1) * digest_length, t, cp_len);
    }

    Sec_Memset(prk, 0, sizeof(prk));
    Sec_Memset(t, 0, sizeof(t));
    return result;
#else
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return SEC_RESULT_FAILURE;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return SEC_RESULT_FAILURE;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, use_salt ? "salt" : nullptr, use_salt ? 4 : 0) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return SEC_RESULT_FAILURE;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return SEC_RESULT_FAILURE;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "label", 5) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return SEC_RESULT_FAILURE;
    }

    size_t length = *out_len;
    if (EVP_PKEY_derive(pctx, out, &length) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return SEC_RESULT_FAILURE;
    }

    EVP_PKEY_CTX_free(pctx);
    return SEC_RESULT_SUCCESS;
#endif
}

Sec_Result testKeyExchangeDH(SEC_OBJECTID idComputed, Sec_StorageLoc loc, Sec_KeyType typeComputed, bool useSalt) {

    TestCtx ctx;
    Sec_KeyExchangeHandle* keyExchangeHandle = nullptr;
    DH* dh = nullptr;
    Sec_Result result = SEC_RESULT_FAILURE;

    Sec_DHParameters dh_params;
    memcpy(dh_params.p, g_dh_p, sizeof(g_dh_p));
    dh_params.pLen = sizeof(g_dh_p);
    memcpy(dh_params.g, g_dh_g, sizeof(g_dh_g));
    dh_params.gLen = sizeof(g_dh_g);

    SEC_BYTE pub_secapi[dh_params.pLen];
    SEC_BYTE pub_test[dh_params.pLen];
    SEC_BYTE ss_test[dh_params.pLen];
    SEC_SIZE ss_len;
    SEC_BYTE derived_key[SecKey_GetKeyLenForKeyType(typeComputed)];
    SEC_SIZE derived_key_len = sizeof(derived_key);
    SEC_SIZE out_len;
    SEC_OBJECTID hkdf_key_id = SEC_OBJECTID_INVALID;

    do {
        if (ctx.init() != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("TestCtx.init failed");
            break;
        }

        result = SecKeyExchange_GetInstance(ctx.proc(), SEC_KEYEXCHANGE_DH, &dh_params, &keyExchangeHandle);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKeyExchange_GetInstance failed");
            break;
        }

        result = SecKeyExchange_GenerateKeys(keyExchangeHandle, pub_secapi, sizeof(pub_secapi));
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKeyExchange_GenerateKeys failed");
            break;
        }

        //create other side info
        dh = DH_create(g_dh_p, sizeof(g_dh_p), g_dh_g, sizeof(g_dh_g));
        if (dh == nullptr) {
            SEC_LOG_ERROR("_DH_create failed");
            break;
        }

        result = DH_generate_key(dh, pub_test, sizeof(pub_test), &out_len);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("_DH_generate_key failed");
            break;
        }

        //compute shared secret
        result = SecKeyExchange_ComputeSecret(keyExchangeHandle, pub_test, out_len, typeComputed, idComputed, loc);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKeyExchange_ComputeSecret failed");
            break;
        }

        hkdf_key_id = SecKey_ObtainFreeObjectId(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_TOP);
        if (hkdf_key_id == SEC_OBJECTID_INVALID) {
            SEC_LOG_ERROR("SecKeyExchange_ComputeSecret failed");
            break;
        }

        result = SecKey_Derive_HKDF_BaseKey(ctx.proc(), hkdf_key_id, typeComputed, loc, SEC_MACALGORITHM_HMAC_SHA256,
                (SEC_BYTE*) (useSalt == SEC_TRUE ? "salt" : nullptr), useSalt == SEC_TRUE ? 4 : 0, // NOLINT
                (SEC_BYTE*) "label", 5, idComputed);                                               // NOLINT
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Derive_HKDF_BaseKey failed");
            break;
        }

        result = DH_compute(dh, pub_secapi, sizeof(pub_secapi), ss_test, sizeof(ss_test), &ss_len);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("_DH_compute failed");
            break;
        }

        result = hkdf(ss_test, ss_len, derived_key, &derived_key_len, useSalt);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("_DH_compute failed");
            break;
        }

        //test enc/dec or mac
        if (SecKey_IsAES(typeComputed) == SEC_TRUE) {
            result = aesKeyCheck(ctx.proc(), hkdf_key_id, derived_key, derived_key_len);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("AesKeyCheck failed");
                break;
            }
        } else {
            result = macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, hkdf_key_id, derived_key, derived_key_len);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("MacCheck failed");
                break;
            }
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyExchangeHandle != nullptr)
        SecKeyExchange_Release(keyExchangeHandle);

    if (hkdf_key_id != SEC_OBJECTID_INVALID)
        SecKey_Delete(ctx.proc(), hkdf_key_id);

    if (dh != nullptr)
        DH_free(dh);

    return result;
}

Sec_Result testKeyExchangeECDH(SEC_OBJECTID idComputed, Sec_StorageLoc loc, Sec_KeyType typeComputed,
        bool useSalt) {
    TestCtx ctx;
    Sec_KeyExchangeHandle* keyExchangeHandle = nullptr;
    EC_KEY* priv_test = nullptr;
    EC_KEY* pub_secapi_key = nullptr;
    Sec_Result result = SEC_RESULT_FAILURE;

    Sec_ECCRawPublicKey pub_secapi;
    Sec_ECCRawPublicKey pub_test;
    SEC_BYTE ss_test[32];
    SEC_SIZE ss_len;
    SEC_OBJECTID hkdf_key_id = SEC_OBJECTID_INVALID;
    SEC_BYTE derived_key[SecKey_GetKeyLenForKeyType(typeComputed)];
    SEC_SIZE derived_key_len = sizeof(derived_key);

    Sec_ECDHParameters ecdh_params;
    ecdh_params.curve = NISTP256;

    do {
        if (ctx.init() != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("TestCtx.init failed");
            break;
        }

        result = SecKeyExchange_GetInstance(ctx.proc(), SEC_KEYEXCHANGE_ECDH, &ecdh_params, &keyExchangeHandle);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKeyExchange_GetInstance failed");
            break;
        }

        result = SecKeyExchange_GenerateKeys(keyExchangeHandle, reinterpret_cast<SEC_BYTE*>(&pub_secapi),
                sizeof(pub_secapi));
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKeyExchange_GenerateKeys failed");
            break;
        }

        //create other side info
        if ((priv_test = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == nullptr) {
            SEC_LOG_ERROR("EC_KEY_new_by_curve_name failed");
            break;
        }

        if (EC_KEY_generate_key(priv_test) != OPENSSL_SUCCESS) {
            SEC_LOG_ERROR("EC_KEY_generate_key failed");
            break;
        }

        if (ECCToPubBinary(priv_test, &pub_test) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("_ECCToPubBinary failed");
            break;
        }

        //compute shared secret
        result = SecKeyExchange_ComputeSecret(keyExchangeHandle, reinterpret_cast<SEC_BYTE*>(&pub_test),
                sizeof(pub_test), typeComputed, idComputed, loc);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKeyExchange_ComputeSecret failed");
            break;
        }

        pub_secapi_key = ECCFromPubBinary(&pub_secapi);
        if (pub_secapi_key == nullptr) {
            SEC_LOG_ERROR("SecUtils_ECCFromPubBinary failed");
            break;
        }

        /* Derive the shared secret */
        ss_len = ECDH_compute_key(ss_test, sizeof(ss_test), EC_KEY_get0_public_key(pub_secapi_key), priv_test, nullptr);
        if (ss_len <= 0) {
            SEC_LOG_ERROR("ECDH_compute_key failed");
            break;
        }

        hkdf_key_id = SecKey_ObtainFreeObjectId(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_TOP);
        if (hkdf_key_id == SEC_OBJECTID_INVALID) {
            SEC_LOG_ERROR("SecKeyExchange_ComputeSecret failed");
            break;
        }

        result = SecKey_Derive_HKDF_BaseKey(ctx.proc(), hkdf_key_id, typeComputed, loc, SEC_MACALGORITHM_HMAC_SHA256,
                (unsigned char*) (useSalt == SEC_TRUE ? "salt" : nullptr), useSalt == SEC_TRUE ? 4 : 0, // NOLINT
                (unsigned char*) "label", 5, idComputed);                                               // NOLINT
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Derive_HKDF_BaseKey failed");
            break;
        }

        result = hkdf(ss_test, ss_len, derived_key, &derived_key_len, useSalt);
        if (result != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("_DH_compute failed");
            break;
        }

        //test enc/dec or mac
        if (SecKey_IsAES(typeComputed) == SEC_TRUE) {
            result = aesKeyCheck(ctx.proc(), hkdf_key_id, derived_key, derived_key_len);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("AesKeyCheck failed");
                break;
            }
        } else {
            result = macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, hkdf_key_id, derived_key, derived_key_len);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("MacCheck failed");
                break;
            }
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyExchangeHandle != nullptr) {
        SecKeyExchange_Release(keyExchangeHandle);
    }

    if (hkdf_key_id != SEC_OBJECTID_INVALID)
        SecKey_Delete(ctx.proc(), hkdf_key_id);

    SEC_ECC_FREE(priv_test);
    SEC_ECC_FREE(pub_secapi_key);

    return result;
}
