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

#include "sec_adapter_pubops.h"

static Sec_Result SecUtils_BigNumToBuffer(const BIGNUM* bignum, SEC_BYTE* buffer, SEC_SIZE buffer_len) {
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

static RSA* SecUtils_RSAFromPubBinary(Sec_RSARawPublicKey* binary) {
    RSA* rsa = NULL;

    rsa = RSA_new();
    if (rsa == NULL) {
        SEC_LOG_ERROR("RSA_new failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(binary->n, (int) Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);
#else
    RSA_set0_key(rsa, BN_bin2bn(binary->n, (int) Sec_BEBytesToUint32(binary->modulus_len_be), NULL),
            BN_bin2bn(binary->e, 4, NULL), NULL);
#endif

    return rsa;
}

static EC_KEY* SecUtils_ECCFromPubBinary(Sec_ECCRawPublicKey* binary) {
    BN_CTX* ctx = BN_CTX_new();

    if (binary->type != SEC_KEYTYPE_ECC_NISTP256_PUBLIC && binary->type != SEC_KEYTYPE_ECC_NISTP256)
        return NULL;

    //create ec_key structure with NIST p256 curve;
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM* xp;
    BIGNUM* yp;

    if (((xp = BN_CTX_get(ctx)) == NULL) || ((yp = BN_CTX_get(ctx)) == NULL)) {
        EC_POINT_free(ec_point);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return NULL;
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

static Sec_Result SecUtils_VerifyX509WithRawECCPublicKey(X509* x509, Sec_ECCRawPublicKey* public_key) {
    EC_KEY* ec_key = NULL;
    EVP_PKEY* evp_key = NULL;
    int verify_res;

    ec_key = SecUtils_ECCFromPubBinary(public_key);
    if (ec_key == NULL) {
        SEC_LOG_ERROR("_SecUtils_ECCFromPubBinary failed");
        SEC_ECC_FREE(ec_key);
        SEC_EVPPKEY_FREE(evp_key);
        return SEC_RESULT_FAILURE;
    }

    evp_key = EVP_PKEY_new();
    if (EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_PKEY_set1_EC_KEY failed");
        SEC_ECC_FREE(ec_key);
        SEC_EVPPKEY_FREE(evp_key);
        return SEC_RESULT_FAILURE;
    }

    verify_res = X509_verify(x509, evp_key);

    SEC_ECC_FREE(ec_key);
    SEC_EVPPKEY_FREE(evp_key);

    if (verify_res != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("X509_verify failed, %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result SecUtils_VerifyX509WithRawRSAPublicKey(X509* x509, Sec_RSARawPublicKey* public_key) {
    RSA* rsa = NULL;
    EVP_PKEY* evp_key = NULL;
    int verify_res;

    rsa = SecUtils_RSAFromPubBinary(public_key);
    if (rsa == NULL) {
        SEC_LOG_ERROR("_Sec_ReadRSAPublic failed");
        SEC_RSA_FREE(rsa);
        SEC_EVPPKEY_FREE(evp_key);
        return SEC_RESULT_FAILURE;
    }

    evp_key = EVP_PKEY_new();
    if (EVP_PKEY_set1_RSA(evp_key, rsa) != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("EVP_PKEY_set1_RSA failed");
        SEC_RSA_FREE(rsa);
        SEC_EVPPKEY_FREE(evp_key);
        return SEC_RESULT_FAILURE;
    }

    verify_res = X509_verify(x509, evp_key);

    SEC_RSA_FREE(rsa);
    SEC_EVPPKEY_FREE(evp_key);

    if (verify_res != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("X509_verify failed, %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result SecUtils_Extract_EC_KEY_X_Y(const EC_KEY* ec_key, BIGNUM** xp, BIGNUM** yp, Sec_KeyType* keyTypep) {
    const EC_GROUP* group = NULL;
    const EC_POINT* ec_point = NULL;
    BN_CTX* ctx = NULL;
    Sec_Result result = SEC_RESULT_FAILURE;

    if (xp == NULL) {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: X cannot be NULL");
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return result;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_group: %s", ERR_error_string(ERR_get_error(), NULL));
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return result;
    }

    ec_point = EC_KEY_get0_public_key(ec_key);
    if (ec_point == NULL) {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_public_key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return result;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        SEC_LOG_ERROR("BN_CTX_new() failed");
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return result;
    }

    *xp = BN_new();
    if (*xp == NULL) {
        SEC_LOG_ERROR("BN_new() failed");
        if (ctx != NULL)
            BN_CTX_free(ctx);

        return result;
    }

    if (yp != NULL) { // if caller wants y coordinate returned
        *yp = BN_new();
        if (*yp == NULL) {
            SEC_LOG_ERROR("BN_new() failed");
            if (ctx != NULL)
                BN_CTX_free(ctx);

            return result;
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

        return result;
    }

    if (ctx != NULL)
        BN_CTX_free(ctx);

    return SEC_RESULT_SUCCESS;
}

static EC_KEY* SecUtils_ECCFromDERPub(const SEC_BYTE* der, SEC_SIZE der_len) {
    const unsigned char* p = (const unsigned char*) der;
    EC_KEY* ec_key = NULL;

    ec_key = d2i_EC_PUBKEY(&ec_key, &p, der_len);

    if (ec_key == NULL) {
        SEC_LOG_ERROR("Invalid ECC key container");
        return NULL;
    }

    return ec_key;
}

Sec_Result Pubops_VerifyX509WithPubEcc(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey* pub) {
    X509* x509 = SecCertificate_DerToX509(cert, cert_len);
    Sec_Result result = SEC_RESULT_FAILURE;

    if (x509 == NULL) {
        SEC_LOG_ERROR("SecCertificate_DerToX509 failed");
        SEC_X509_FREE(x509);
        return result;
    }

    if (SecUtils_VerifyX509WithRawECCPublicKey(x509, pub) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("_SecUtils_VerifyX509WithRawECCPublicKey failed");
        SEC_X509_FREE(x509);
        return result;
    }

    SEC_X509_FREE(x509);
    return SEC_RESULT_SUCCESS;
}

Sec_Result Pubops_ExtractRSAPubFromX509Der(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_RSARawPublicKey* pub) {
    X509* x509 = SecCertificate_DerToX509(cert, cert_len);
    EVP_PKEY* evp_key = NULL;
    RSA* rsa = NULL;
    Sec_Result result = SEC_RESULT_FAILURE;

    if (x509 == NULL) {
        SEC_LOG_ERROR("SecCertificate_DerToX509 failed");
        SEC_X509_FREE(x509);
        SEC_EVPPKEY_FREE(evp_key);
        SEC_RSA_FREE(rsa);
        return result;
    }

    evp_key = X509_get_pubkey(x509);
    if (evp_key == NULL) {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        SEC_X509_FREE(x509);
        SEC_EVPPKEY_FREE(evp_key);
        SEC_RSA_FREE(rsa);
        return result;
    }

    rsa = EVP_PKEY_get1_RSA(evp_key);
    if (rsa == NULL) {
        SEC_X509_FREE(x509);
        SEC_EVPPKEY_FREE(evp_key);
        SEC_RSA_FREE(rsa);
        return result;
    }

    Sec_Uint32ToBEBytes(RSA_size(rsa), pub->modulus_len_be);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SecUtils_BigNumToBuffer(rsa->n, pub->n, Sec_BEBytesToUint32(pub->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, pub->e, 4);
#else
    SecUtils_BigNumToBuffer(RSA_get0_n(rsa), pub->n, Sec_BEBytesToUint32(pub->modulus_len_be));
    SecUtils_BigNumToBuffer(RSA_get0_e(rsa), pub->e, 4);
#endif

    SEC_X509_FREE(x509);
    SEC_EVPPKEY_FREE(evp_key);
    SEC_RSA_FREE(rsa);
    return SEC_RESULT_SUCCESS;
}

Sec_Result Pubops_ExtractECCPubFromX509Der(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey* pub) {
    X509* x509 = SecCertificate_DerToX509(cert, cert_len);
    Sec_Result result = SEC_RESULT_FAILURE;

    if (x509 == NULL) {
        SEC_LOG_ERROR("SecCertificate_DerToX509 failed");
        SEC_X509_FREE(x509);
        return result;
    }

    EVP_PKEY* evp_key = X509_get_pubkey(x509);
    if (evp_key == NULL) {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        SEC_X509_FREE(x509);
        SEC_EVPPKEY_FREE(evp_key);
        return result;
    }

    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(evp_key);
    if (ec_key == NULL) {
        SEC_X509_FREE(x509);
        SEC_EVPPKEY_FREE(evp_key);
        SEC_ECC_FREE(ec_key);
        return result;
    }

    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    Sec_KeyType key_type;
    if (SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, &key_type) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y failed");
        if (x != NULL)
            BN_clear_free(x);

        if (y != NULL)
            BN_clear_free(y);

        SEC_X509_FREE(x509);
        SEC_EVPPKEY_FREE(evp_key);
        SEC_ECC_FREE(ec_key);
        return result;
    }

    pub->type = key_type;

    Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(key_type), pub->key_len);
    SecUtils_BigNumToBuffer(x, pub->x, Sec_BEBytesToUint32(pub->key_len));
    SecUtils_BigNumToBuffer(y, pub->y, Sec_BEBytesToUint32(pub->key_len));

    if (x != NULL)
        BN_clear_free(x);

    if (y != NULL)
        BN_clear_free(y);

    SEC_X509_FREE(x509);
    SEC_EVPPKEY_FREE(evp_key);
    SEC_ECC_FREE(ec_key);
    return SEC_RESULT_SUCCESS;
}

static RSA* SecUtils_RSAFromDERPub(const SEC_BYTE* der, SEC_SIZE der_len) {
    const unsigned char* p = (const unsigned char*) der;
    RSA* rsa = NULL;

    rsa = d2i_RSAPublicKey(&rsa, &p, der_len);

    if (!rsa) {
        p = (const unsigned char*) der;
        rsa = d2i_RSA_PUBKEY(&rsa, &p, der_len);
    }

    if (!rsa) {
        SEC_LOG_ERROR("Invalid RSA key container");
        return rsa;
    }

    return rsa;
}

Sec_Result Pubops_VerifyX509WithPubRsa(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_RSARawPublicKey* pub) {
    X509* x509 = SecCertificate_DerToX509(cert, cert_len);
    Sec_Result result = SEC_RESULT_FAILURE;

    if (x509 == NULL) {
        SEC_LOG_ERROR("SecCertificate_DerToX509 failed");
        SEC_X509_FREE(x509);
        return result;
    }

    if (SecUtils_VerifyX509WithRawRSAPublicKey(x509, pub) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("_SecUtils_VerifyX509WithRawRSAPublicKey failed");
        SEC_X509_FREE(x509);
        return result;
    }

    SEC_X509_FREE(x509);
    return SEC_RESULT_SUCCESS;
}

Sec_Result Pubops_ExtractRSAPubFromPUBKEYDer(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_RSARawPublicKey* pub) {
    RSA* rsa = SecUtils_RSAFromDERPub(cert, cert_len);
    Sec_Result result = SEC_RESULT_FAILURE;
    if (rsa == NULL) {
        SEC_LOG_ERROR("_SecUtils_RSAFromDERPub failed");
        SEC_RSA_FREE(rsa);
        return result;
    }

    Sec_Uint32ToBEBytes(RSA_size(rsa), pub->modulus_len_be);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SecUtils_BigNumToBuffer(rsa->n, pub->n, Sec_BEBytesToUint32(pub->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, pub->e, 4);
#else
    SecUtils_BigNumToBuffer(RSA_get0_n(rsa), pub->n, Sec_BEBytesToUint32(pub->modulus_len_be));
    SecUtils_BigNumToBuffer(RSA_get0_e(rsa), pub->e, 4);
#endif

    SEC_RSA_FREE(rsa);
    return SEC_RESULT_SUCCESS;
}

Sec_Result Pubops_ExtractECCPubFromPUBKEYDer(SEC_BYTE* cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey* pub) {
    EC_KEY* ec_key = SecUtils_ECCFromDERPub(cert, cert_len);
    Sec_Result result = SEC_RESULT_FAILURE;
    if (ec_key == NULL) {
        SEC_LOG_ERROR("_SecUtils_ECCFromDERPub failed");
        SEC_ECC_FREE(ec_key);
        return result;
    }

    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    Sec_KeyType key_type;
    if (SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, &key_type) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y failed");
        if (x != NULL)
            BN_clear_free(x);

        if (y != NULL)
            BN_clear_free(y);

        SEC_ECC_FREE(ec_key);
        return result;
    }

    pub->type = key_type;

    Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(key_type), pub->key_len);
    SecUtils_BigNumToBuffer(x, pub->x, Sec_BEBytesToUint32(pub->key_len));
    SecUtils_BigNumToBuffer(y, pub->y, Sec_BEBytesToUint32(pub->key_len));

    if (x != NULL)
        BN_clear_free(x);

    if (y != NULL)
        BN_clear_free(y);

    SEC_ECC_FREE(ec_key);
    return SEC_RESULT_SUCCESS;
}

Sec_Result Pubops_VerifyWithPubRsa(RSA* rsa, Sec_SignatureAlgorithm alg, SEC_BYTE* digest, SEC_SIZE digest_len,
        SEC_BYTE* sig, SEC_SIZE sig_len, int salt_len) {
    if (rsa == NULL) {
        SEC_LOG_ERROR("_SecUtils_RSAFromPubBinary failed");
        return SEC_RESULT_FAILURE;
    }

    int expected_sign_len = RSA_size(rsa);
    if (sig_len != expected_sign_len) {
        SEC_LOG_ERROR("Invalid signature size %d, expected %d", sig_len, expected_sign_len);
        return SEC_RESULT_FAILURE;
    }

    Sec_DigestAlgorithm digest_alg = SecSignature_GetDigestAlgorithm(alg);

    if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS ||
            alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST ||
            alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS ||
            alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST) {
        //pss padding
        SEC_BYTE decrypted[SEC_RSA_KEY_MAX_LEN];
        if (RSA_public_decrypt(RSA_size(rsa), sig, decrypted, rsa, RSA_NO_PADDING) == -1) {
            SEC_LOG_ERROR("RSA_public_decrypt failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
            return SEC_RESULT_FAILURE;
        }

        if (salt_len < 0) {
            salt_len = (digest_alg == SEC_DIGESTALGORITHM_SHA1) ? 20 : 32;
        }

        /* verify the data */
        int openssl_res = RSA_verify_PKCS1_PSS(rsa, digest,
                (digest_alg == SEC_DIGESTALGORITHM_SHA1) ? EVP_sha1() : EVP_sha256(),
                decrypted, salt_len);
        if (openssl_res != OPENSSL_SUCCESS) {
            SEC_LOG_ERROR("RSA_verify_PKCS1_PSS failed");
            SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
            return SEC_RESULT_FAILURE;
        }
    } else {
        int openssl_res = RSA_verify((digest_alg == SEC_DIGESTALGORITHM_SHA1) ? NID_sha1 : NID_sha256, digest,
                digest_len, sig, sig_len, rsa);
        if (openssl_res != OPENSSL_SUCCESS) {
            SEC_LOG_ERROR("RSA_verify failed");
            SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
            return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result Pubops_VerifyWithPubEcc(EC_KEY* ec_key, Sec_SignatureAlgorithm alg, SEC_BYTE* digest, SEC_SIZE digest_len,
        SEC_BYTE* sig, SEC_SIZE sig_len) {
    if (ec_key == NULL) {
        SEC_LOG_ERROR("_SecUtils_ECCFromPubBinary failed");
        return SEC_RESULT_FAILURE;
    }

    int expected_sign_len = 2 * EC_GROUP_get_degree(EC_KEY_get0_group(ec_key)) / 8;
    if (sig_len != expected_sign_len) {
        SEC_LOG_ERROR("Invalid signature size  %d, expected %d", sig_len, expected_sign_len);
        return SEC_RESULT_FAILURE;
    }

    ECDSA_SIG* esig = ECDSA_SIG_new();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_bin2bn(&sig[0], SEC_ECC_NISTP256_KEY_LEN, esig->r);
    BN_bin2bn(&sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN, esig->s);
#else
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BN_bin2bn(&sig[0], SEC_ECC_NISTP256_KEY_LEN, r);
    BN_bin2bn(&sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN, s);
    ECDSA_SIG_set0(esig, r, s);
#endif
    int openssl_res = ECDSA_do_verify(digest, (int) digest_len, esig, ec_key);

    // Automatically frees r & s.
    ECDSA_SIG_free(esig);
    if (openssl_res != OPENSSL_SUCCESS) {
        SEC_LOG_ERROR("ECDSA_do_verify failed");

        if (-1 == openssl_res) { // -1 is not an "error", just a verification failure, so don't log as much
            SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        }

        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result Pubops_HMAC(Sec_MacAlgorithm alg, SEC_BYTE* key, SEC_SIZE key_len, SEC_BYTE* input, SEC_SIZE input_len,
        SEC_BYTE* mac, SEC_SIZE mac_len) {
    switch (alg) {
        case SEC_MACALGORITHM_HMAC_SHA1:
        case SEC_MACALGORITHM_HMAC_SHA256: {
            unsigned int osl_mac_len = mac_len;
            if (HMAC(alg == SEC_MACALGORITHM_HMAC_SHA1 ? EVP_sha1() : EVP_sha256(), key, (int) key_len, input,
                        input_len, mac, &osl_mac_len) == NULL) {
                SEC_LOG_ERROR("HMAC failed");
                SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
                return SEC_RESULT_FAILURE;
            }

            break;
        }

        case SEC_MACALGORITHM_CMAC_AES_128: {
            CMAC_CTX* cmac_ctx = CMAC_CTX_new();

            if (CMAC_Init(cmac_ctx, &key[0], key_len,
                        key_len == SEC_AES_BLOCK_SIZE ? EVP_aes_128_cbc() : EVP_aes_256_cbc(),
                        NULL) != OPENSSL_SUCCESS) {
                SEC_LOG_ERROR("Comcast_CMAC_Init failed");
                return SEC_RESULT_FAILURE;
            }

            if (CMAC_Update(cmac_ctx, &input[0], input_len) != OPENSSL_SUCCESS) {
                SEC_LOG_ERROR("CMAC_Update failed");
                CMAC_CTX_free(cmac_ctx);
                return SEC_RESULT_FAILURE;
            }

            size_t outl = mac_len;
            if (CMAC_Final(cmac_ctx, &mac[0], &outl) != OPENSSL_SUCCESS) {
                SEC_LOG_ERROR("CMAC_Final failed");
                CMAC_CTX_free(cmac_ctx);
                return SEC_RESULT_FAILURE;
            }

            CMAC_CTX_free(cmac_ctx);
            break;
        }

        default:
            SEC_LOG_ERROR("Unknown algorithm encountered: %d", alg);
            return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result Pubops_ExtractECCPubToPUBKEYDer(Sec_ECCRawPublicKey* eccRawPublicKey, SEC_BYTE** out, SEC_SIZE* outLength) {

    size_t temp_ec_public_length = Sec_BEBytesToUint32(eccRawPublicKey->key_len);
    SEC_BYTE temp_ec_public[temp_ec_public_length * 2 + 1];
    temp_ec_public[0] = POINT_CONVERSION_UNCOMPRESSED;
    memcpy(temp_ec_public + 1, eccRawPublicKey->x, temp_ec_public_length);
    memcpy(temp_ec_public + 1 + temp_ec_public_length, eccRawPublicKey->y, temp_ec_public_length);
    const unsigned char* p_temp_ec_public = temp_ec_public;
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (o2i_ECPublicKey(&ec_key, &p_temp_ec_public, (long) temp_ec_public_length * 2 + 1) == NULL) {
        SEC_LOG_ERROR("o2i_ECPublicKey failed");
        return SEC_RESULT_FAILURE;
    }

    *outLength = i2d_EC_PUBKEY(ec_key, NULL);
    if (outLength <= 0) {
        EC_KEY_free(ec_key);
        SEC_LOG_ERROR("i2d_EC_PUBKEY failed");
        return SEC_RESULT_FAILURE;
    }

    *out = malloc(*outLength);
    if (*out == NULL) {
        SEC_LOG_ERROR("i2d_EC_PUBKEY failed");
        EC_KEY_free(ec_key);
        return SEC_RESULT_FAILURE;
    }

    unsigned char* p_other_public = *out;
    *outLength = i2d_EC_PUBKEY(ec_key, &p_other_public);
    EC_KEY_free(ec_key);
    if (*outLength <= 0) {
        SEC_LOG_ERROR("i2d_EC_PUBKEY failed");
        free(*out);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}
