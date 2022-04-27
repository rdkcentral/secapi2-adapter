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

#include "cert.h"
#include "sec_adapter_utils.h"
#include "test_creds.h"
#include "test_ctx.h"

static X509* DerToX509(SEC_BYTE* der, SEC_SIZE der_len) {
    BIO* bio;
    X509* x509;

    bio = BIO_new_mem_buf(der, static_cast<int>(der_len));
    x509 = d2i_X509_bio(bio, nullptr);
    SEC_BIO_FREE(bio);

    if (x509 == nullptr) {
        SEC_LOG_ERROR("d2i_X509_bio failed");
    }

    return x509;
}

Sec_Result testCertProvision(SEC_OBJECTID id, TestCert cert, Sec_StorageLoc loc) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (ctx.provisionCert(id, loc, cert) == nullptr) {
        SEC_LOG_ERROR("TestCtx.provisionCert failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCertExport(SEC_OBJECTID id, TestCert cert, Sec_StorageLoc loc) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_CertificateHandle* certificateHandle;
    if ((certificateHandle = ctx.provisionCert(id, loc, cert)) == nullptr) {
        SEC_LOG_ERROR("TestCtx.provisionCert failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_SIZE written;
    if (SecCertificate_Export(certificateHandle, nullptr, 0, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_Export failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> out;
    out.resize(written);
    if (SecCertificate_Export(certificateHandle, &out[0], out.size(), &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecBundle_Export failed");
        return SEC_RESULT_FAILURE;
    }

    X509* x509 = DerToX509(&out[0], out.size());
    if (x509 == nullptr) {
        SEC_LOG_ERROR("DerToX509 failed");
        return SEC_RESULT_FAILURE;
    }
    SEC_X509_FREE(x509);

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCertExportNoSha(SEC_OBJECTID id, TestCert cert) {
    TestCtx ctx;
    if (ctx.init("/tmp/sec_api_test_global", "/tmp/sec_api_test_app") != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_CertificateHandle* certificateHandle;
    if ((certificateHandle = ctx.provisionCert(id, SEC_STORAGELOC_FILE, cert)) == nullptr) {
        SEC_LOG_ERROR("TestCtx.provisionCert failed");
        return SEC_RESULT_FAILURE;
    }

    ctx.releaseCert(certificateHandle);

    char file_name_verification[SEC_MAX_FILE_PATH_LEN];
    snprintf(file_name_verification, sizeof(file_name_verification), SEC_VERIFICATION_FILENAME_PATTERN,
            "/tmp/sec_api_test_app/", id);
    SecUtils_RmFile(file_name_verification);
    if ((certificateHandle = ctx.getCert(id)) == nullptr) {
        SEC_LOG_ERROR("ctx.getCert failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_SIZE written;
    if (SecCertificate_Export(certificateHandle, nullptr, 0, &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_Export failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> out;
    out.resize(written);
    if (SecCertificate_Export(certificateHandle, &out[0], out.size(), &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_Export failed");
        return SEC_RESULT_FAILURE;
    }

    X509* x509 = DerToX509(&out[0], out.size());
    if (x509 == nullptr) {
        SEC_LOG_ERROR("_DerToX509 failed");
        return SEC_RESULT_FAILURE;
    }
    SEC_X509_FREE(x509);

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCertVerify(SEC_OBJECTID id_cert, TestCert cert, SEC_OBJECTID id_key, TestKey key, Sec_StorageLoc loc) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_CertificateHandle* certificateHandle;
    if ((certificateHandle = ctx.provisionCert(id_cert, SEC_STORAGELOC_RAM, cert)) == nullptr) {
        SEC_LOG_ERROR("TestCtx.provisionCert failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandle;
    if ((keyHandle = ctx.provisionKey(id_key, loc, key, TESTKC_RAW)) == nullptr) {
        SEC_LOG_ERROR("TestCtx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_IsEcc(TestCreds::getKeyType(key)) != 0) {
        Sec_ECCRawPublicKey pub_key;
        if (SecCertificate_ExtractECCPublicKey(certificateHandle, &pub_key) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCertificate_ExtractECCPublicKey failed");
            return SEC_RESULT_FAILURE;
        }

        if (SecCertificate_VerifyWithRawECCPublicKey(certificateHandle, &pub_key) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCertificate_VerifyWithRawECCPublicKey failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        Sec_RSARawPublicKey pub_key;
        if (SecCertificate_ExtractRSAPublicKey(certificateHandle, &pub_key) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCertificate_ExtractRSAPublicKey failed");
            return SEC_RESULT_FAILURE;
        }

        if (SecCertificate_VerifyWithRawRSAPublicKey(certificateHandle, &pub_key) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCertificate_VerifyWithRawRSAPublicKey failed");
            return SEC_RESULT_FAILURE;
        }
    }

    if (SecCertificate_Verify(certificateHandle, keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_Verify failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCertSignWithPkcs7(SEC_OBJECTID id_cert, TestCert cert, SEC_OBJECTID id_key, TestKey key,
        Sec_StorageLoc loc) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_CertificateHandle* certificateHandle;
    if ((certificateHandle = ctx.provisionCert(id_cert, SEC_STORAGELOC_RAM, cert)) == nullptr) {
        SEC_LOG_ERROR("TestCtx.provisionCert failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle* keyHandle;
    if ((keyHandle = ctx.provisionKey(id_key, loc, key, TESTKC_RAW)) == nullptr) {
        SEC_LOG_ERROR("TestCtx.provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    X509* x509Cert = nullptr;
    RSA* rsa;
    EVP_PKEY* evp;
    BIO* bio = nullptr;
    BIO* out = nullptr;
    PKCS7* pkcs7 = nullptr;
    int length;
    Sec_Result result;
    std::vector<SEC_BYTE> input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    unsigned char* message = nullptr;
    unsigned char* messagePtr;

    do {
        rsa = SecKey_ToEngineRSAWithCert(keyHandle, certificateHandle);
        evp = EVP_PKEY_new();
        if (EVP_PKEY_assign(evp, EVP_PKEY_RSA, rsa) != 1) {
            SEC_LOG_ERROR("EVP_PKEY_assign failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        rsa = nullptr;

        x509Cert = SecCertificate_ToX509(certificateHandle);
        if (x509Cert == nullptr) {
            SEC_LOG_ERROR("SecCertificate_ToX509 failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        /* signed message */
        bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
        if (bio == nullptr) {
            SEC_LOG_ERROR("BIO_new_mem_buf failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        pkcs7 = PKCS7_sign(x509Cert, evp, nullptr, bio, PKCS7_BINARY);
        if (pkcs7 == nullptr) {
            SEC_LOG_ERROR("PKCS7_sign failed: %s", ERR_error_string(ERR_get_error(), NULL));
            result = SEC_RESULT_FAILURE;
            break;
        }

        length = i2d_PKCS7(pkcs7, nullptr);
        if (length < 0) {
            SEC_LOG_ERROR("i2d_PKCS7 failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        message = static_cast<unsigned char*>(malloc(length));
        messagePtr = message;
        length = i2d_PKCS7(pkcs7, &messagePtr);
        if (length < 0) {
            SEC_LOG_ERROR("i2d_PKCS7 failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        out = BIO_new(BIO_s_mem());
        if (PKCS7_verify(pkcs7, nullptr, nullptr, nullptr, out, PKCS7_NOVERIFY) != 1) {
            SEC_LOG_ERROR("PKCS7_verify failed");
            result = SEC_RESULT_FAILURE;
            break;
        }

        BUF_MEM* bptr;
        BIO_ctrl(out, BIO_C_GET_BUF_MEM_PTR, 0, &bptr);
        if (memcmp(bptr->data, input.data(), input.size()) != 0) {
            SEC_LOG_ERROR("data mismatch");
            result = SEC_RESULT_FAILURE;
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    SEC_RSA_FREE(rsa);
    SEC_EVPPKEY_FREE(evp);
    SEC_X509_FREE(x509Cert);
    SEC_BIO_FREE(bio);
    SEC_BIO_FREE(out);
    if (pkcs7 != nullptr)
        PKCS7_free(pkcs7);

    if (message != nullptr)
        free(message);
    return result;
}
