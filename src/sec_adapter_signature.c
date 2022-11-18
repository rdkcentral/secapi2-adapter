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

#include "sec_adapter_processor.h"
#include "sec_adapter_pubops.h"
#include "sec_security.h"
#include "sec_security_utils.h"
#include <memory.h>
#include <openssl/sha.h>

struct Sec_SignatureHandle_struct {
    Sec_ProcessorHandle* processorHandle;
    Sec_SignatureAlgorithm algorithm;
    Sec_SignatureMode mode;
    Sec_KeyHandle* keyHandle;
};

static Sec_KeyContainer get_rsa_public_key_container_for_byte_length(SEC_BYTE* numBytes);

/**
 * @brief Obtain a handle to the signature calculator.
 *
 * @param processorHandle secure processor handle.
 * @param algorithm signing algorithm.
 * @param mode signing mode.
 * @param keyHandle key used for signing operations.
 * @param signatureHandle output signature handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecSignature_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_SignatureAlgorithm algorithm,
        Sec_SignatureMode mode, Sec_KeyHandle* keyHandle, Sec_SignatureHandle** signatureHandle) {
    CHECK_PROCHANDLE(processorHandle)

    Sec_KeyType key_type = SecKey_GetKeyType(keyHandle);
    if (SecSignature_IsValidKey(key_type, algorithm, mode) != SEC_RESULT_SUCCESS) {
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    *signatureHandle = calloc(1, sizeof(Sec_SignatureHandle));
    if (*signatureHandle == NULL) {
        SEC_LOG_ERROR("Calloc failed");
        return SEC_RESULT_FAILURE;
    }

    (*signatureHandle)->processorHandle = processorHandle;
    (*signatureHandle)->algorithm = algorithm;
    (*signatureHandle)->mode = mode;
    (*signatureHandle)->keyHandle = keyHandle;

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Sign/Verify Signature of the input data.
 *
 * @param signatureHandle signature handle.
 * @param input pointer to the input buffer whose signature we are generating/verifying.
 * @param inputSize the length of the input.
 * @param signature buffer where signature is/will be stored.
 * @param signatureSize output variable that will be set to the signature size.
 *
 * @return The status of the operation.
 */
Sec_Result SecSignature_Process(Sec_SignatureHandle* signatureHandle, SEC_BYTE* input, SEC_SIZE inputSize,
        SEC_BYTE* signature, SEC_SIZE* signatureSize) {
    CHECK_HANDLE(signatureHandle)

    if (signatureHandle->mode == SEC_SIGNATUREMODE_SIGN) {
        sa_signature_algorithm signature_algorithm;
        sa_sign_parameters_rsa_pss rsa_pss_parameters;
        sa_sign_parameters_rsa_pkcs1v15 rsa_pkcs1v15_parameters;
        sa_sign_parameters_ecdsa ecdsa_parameters;
        void* parameters = NULL;
        switch (signatureHandle->algorithm) {
            case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
            case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15;
                rsa_pkcs1v15_parameters.digest_algorithm = SA_DIGEST_ALGORITHM_SHA1;
                rsa_pkcs1v15_parameters.precomputed_digest =
                        (signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST);
                parameters = &rsa_pkcs1v15_parameters;
                break;

            case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS:
            case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST:
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PSS;
                rsa_pss_parameters.digest_algorithm = SA_DIGEST_ALGORITHM_SHA1;
                rsa_pss_parameters.mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA1;
                rsa_pss_parameters.precomputed_digest =
                        (signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST);
                rsa_pss_parameters.salt_length = SHA_DIGEST_LENGTH;
                parameters = &rsa_pss_parameters;
                break;

            case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
            case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15;
                rsa_pkcs1v15_parameters.digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;
                rsa_pkcs1v15_parameters.precomputed_digest =
                        (signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST);
                parameters = &rsa_pkcs1v15_parameters;
                break;

            case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS:
            case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST:
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PSS;
                rsa_pss_parameters.digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;
                rsa_pss_parameters.mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;
                rsa_pss_parameters.precomputed_digest =
                        (signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST);
                rsa_pss_parameters.salt_length = SHA256_DIGEST_LENGTH;
                parameters = &rsa_pss_parameters;
                break;

            case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256:
            case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST:
                signature_algorithm = SA_SIGNATURE_ALGORITHM_ECDSA;
                ecdsa_parameters.digest_algorithm = SA_DIGEST_ALGORITHM_SHA256;
                ecdsa_parameters.precomputed_digest =
                        (signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST);
                parameters = &ecdsa_parameters;
                break;

            default:
                return SEC_RESULT_INVALID_PARAMETERS;
        }

        size_t out_length = 0;
        const Sec_Key* key = get_key(signatureHandle->keyHandle);
        // Get the out_length since it is not given to us.
        sa_status status = sa_invoke(signatureHandle->processorHandle, SA_CRYPTO_SIGN, NULL, &out_length,
                signature_algorithm, key->handle, input, inputSize, parameters);
        CHECK_STATUS(status)
        status = sa_invoke(signatureHandle->processorHandle, SA_CRYPTO_SIGN, signature, &out_length,
                signature_algorithm, key->handle, input, inputSize, parameters);
        CHECK_STATUS(status)
        *signatureSize = out_length;
    } else {
        Sec_Result result;
        SEC_BYTE digest[SEC_DIGEST_MAX_LEN];
        SEC_SIZE digest_len;
        if (SecSignature_IsDigest(signatureHandle->algorithm)) {
            if (SecDigest_GetDigestLenForAlgorithm(SecSignature_GetDigestAlgorithm(signatureHandle->algorithm)) !=
                    inputSize) {
                SEC_LOG_ERROR("Invalid input length");
                return SEC_RESULT_FAILURE;
            }

            memcpy(digest, input, inputSize);
            digest_len = inputSize;
        } else {
            /* calculate digest */
            result = SecDigest_SingleInput(signatureHandle->processorHandle,
                    SecSignature_GetDigestAlgorithm(signatureHandle->algorithm), input,
                    inputSize, digest, &digest_len);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecDigest_SingleInput failed");
                return result;
            }
        }

        const Sec_Key* key = get_key(signatureHandle->keyHandle);
        if (SecSignature_IsRsa(signatureHandle->algorithm)) {
            result = Pubops_VerifyWithPubRsa(key->rsa, signatureHandle->algorithm,
                    digest, digest_len, signature, *signatureSize, -1);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("Pubops_VerifyWithPubRsa failed");
                return SEC_RESULT_VERIFICATION_FAILED;
            }
        } else if (SecSignature_IsEcc(signatureHandle->algorithm)) {
            if (*signatureSize != SecSignature_GetEccSignatureSize(signatureHandle->algorithm)) {
                SEC_LOG_ERROR("Incorrect ECC signature size");
                return SEC_RESULT_FAILURE;
            }

            Sec_KeyType key_type = SecKey_GetKeyType(signatureHandle->keyHandle);
            EC_KEY* ec_key = NULL;
            if (SecKey_IsPubEcc(key_type)) {
                ec_key = EC_KEY_new();
                EC_KEY_copy(ec_key, key->ec_key);
            } else {
                Sec_ECCRawPublicKey public_key;
                result = SecKey_ExtractECCPublicKey(signatureHandle->keyHandle, &public_key);
                if (result != SEC_RESULT_SUCCESS) {
                    SEC_LOG_ERROR("SecDigest_SingleInput failed");
                    SEC_ECC_FREE(ec_key);
                    return result;
                }

                ec_key = SecUtils_ECCFromPubBinary(&public_key);
            }

            result = Pubops_VerifyWithPubEcc(ec_key, signatureHandle->algorithm,
                    digest, digest_len, signature, *signatureSize);
            if (result != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("Pubops_VerifyWithPubEcc failed");
                SEC_ECC_FREE(ec_key);
                return SEC_RESULT_VERIFICATION_FAILED;
            }

            SEC_ECC_FREE(ec_key);
        } else {
            SEC_LOG_ERROR("Unimplemented signature algorithm for verify");
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Release the signature object.
 *
 * @param signatureHandle cipher handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecSignature_Release(Sec_SignatureHandle* signatureHandle) {
    CHECK_HANDLE(signatureHandle)
    SEC_FREE(signatureHandle);
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Checks whether the passed in key is valid for a chosen signing algorithm and mode.
 *
 * @param key_type key type.
 * @param algorithm signing algorithm.
 * @param mode signing mode.
 *
 * @return status of the operation.
 */
Sec_Result SecSignature_IsValidKey(Sec_KeyType key_type,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode) {
    switch (algorithm) {
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST:
            if (mode == SEC_SIGNATUREMODE_SIGN) {
                if (key_type == SEC_KEYTYPE_RSA_1024 || key_type == SEC_KEYTYPE_RSA_2048 ||
                        key_type == SEC_KEYTYPE_RSA_3072)
                    return SEC_RESULT_SUCCESS;

                return SEC_RESULT_FAILURE;
            } else {
                if (key_type == SEC_KEYTYPE_RSA_1024 || key_type == SEC_KEYTYPE_RSA_2048 ||
                        key_type == SEC_KEYTYPE_RSA_3072 || key_type == SEC_KEYTYPE_RSA_1024_PUBLIC ||
                        key_type == SEC_KEYTYPE_RSA_2048_PUBLIC || key_type == SEC_KEYTYPE_RSA_3072_PUBLIC)
                    return SEC_RESULT_SUCCESS;

                return SEC_RESULT_FAILURE;
            }

        case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256:
        case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST:
            if (mode == SEC_SIGNATUREMODE_SIGN) {
                if (key_type == SEC_KEYTYPE_ECC_NISTP256)
                    return SEC_RESULT_SUCCESS;

                return SEC_RESULT_FAILURE;
            } else {
                if (key_type == SEC_KEYTYPE_ECC_NISTP256 || key_type == SEC_KEYTYPE_ECC_NISTP256_PUBLIC)
                    return SEC_RESULT_SUCCESS;

                return SEC_RESULT_FAILURE;
            }

        default:
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }
}

/**
 * @brief Returns TRUE if the signature algorithm is an RSA variant.
 *
 * @param alg signing algorithm.
 *
 * @return true if RSA.
 */
SEC_BOOL SecSignature_IsRsa(Sec_SignatureAlgorithm alg) {
    return alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST ||
           alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST ||
           alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST ||
           alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST;
}

/**
 * @brief Returns TRUE if the signature algorithm is an ECC variant.
 *
 * @param alg signing algorithm.
 *
 * @return true if ECC.
 */
SEC_BOOL SecSignature_IsEcc(Sec_SignatureAlgorithm alg) {
    return alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256 || alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST;
}

/**
 * @brief Returns the size of the algorithm's ECC signature.
 *
 * @param alg signing algorithm.
 *
 * @return size in bytes or 0 if unsupported algorithm.
 */
SEC_SIZE SecSignature_GetEccSignatureSize(Sec_SignatureAlgorithm alg) {
    switch (alg) {
        case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256:
        case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST:
            return SEC_ECC_NISTP256_KEY_LEN + SEC_ECC_NISTP256_KEY_LEN;

        default:
            return 0;
    }
}

/**
 * @brief Obtain a digest algorithm used by a specific signing algorithm.
 *
 * @param alg signing algorithm.
 *
 * @return digest algorithm used.
 */
Sec_DigestAlgorithm SecSignature_GetDigestAlgorithm(Sec_SignatureAlgorithm alg) {
    switch (alg) {
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST:
            return SEC_DIGESTALGORITHM_SHA1;

        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST:
        case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256:
        case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST:
            return SEC_DIGESTALGORITHM_SHA256;

        default:
            SEC_LOG_ERROR("Unexpected alg encountered: %d", alg);
            return SEC_DIGESTALGORITHM_NUM;
    }
}

/**
 * @brief Signature util that handles Sec_SignatureHandle generation and release.
 *
 * @param processorHandle processor handle.
 * @param algorithm signing algorithm.
 * @param mode signing mode.
 * @param keyHandle key used for signing operations.
 * @param input pointer to the input buffer whose signature we are generating/verifying.
 * @param inputSize the length of the input.
 * @param signature buffer where signature is/will be stored.
 * @param signatureSize output variable that will be set to the signature size.
 *
 * @return The status of the operation.
 */
Sec_Result SecSignature_SingleInput(Sec_ProcessorHandle* processorHandle, Sec_SignatureAlgorithm algorithm,
        Sec_SignatureMode mode, Sec_KeyHandle* keyHandle, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE* signatureSize) {
    Sec_Result result = SEC_RESULT_FAILURE;
    Sec_SignatureHandle* signatureHandle = NULL;

    if (SecSignature_GetInstance(processorHandle, algorithm, mode, keyHandle, &signatureHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_GetInstance failed");
        if (signatureHandle != NULL)
            SecSignature_Release(signatureHandle);

        return result;
    }

    if (SecSignature_Process(signatureHandle, input, inputSize, signature, signatureSize) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_Process failed");
        if (signatureHandle != NULL)
            SecSignature_Release(signatureHandle);

        return result;
    }

    if (signatureHandle != NULL)
        SecSignature_Release(signatureHandle);

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecSignature_SingleInputCert(Sec_ProcessorHandle* processorHandle, Sec_SignatureAlgorithm algorithm,
        Sec_SignatureMode mode, Sec_CertificateHandle* certificateHandle, SEC_BYTE* input, SEC_SIZE inputSize,
        SEC_BYTE* signature, SEC_SIZE* signatureSize) {
    Sec_KeyHandle* keyHandle = NULL;
    Sec_RSARawPublicKey rsa_public_key;
    Sec_ECCRawPublicKey ecc_public_key;
    CHECK_PROCHANDLE(processorHandle)

    if (mode == SEC_SIGNATUREMODE_SIGN) { // Sanity check: This does not handle SIGN
        SEC_LOG_ERROR("SecSignature_SingleInputCert does not support SEC_SIGNATUREMODE_SIGN");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyType key_type = SecCertificate_GetKeyType(certificateHandle);
    switch (key_type) {
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            if (SecCertificate_ExtractRSAPublicKey(certificateHandle, &rsa_public_key) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecCertificate_ExtractRSAPublicKey failed");
                return SEC_RESULT_FAILURE;
            }

            Sec_KeyContainer key_container = get_rsa_public_key_container_for_byte_length(
                    rsa_public_key.modulus_len_be);
            if (SecKey_Provision(processorHandle, SEC_OBJECTID_SIG_FROM_CERT, SEC_STORAGELOC_RAM_SOFT_WRAPPED,
                        key_container, (SEC_BYTE*) &rsa_public_key, sizeof(rsa_public_key)) !=
                    SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                return SEC_RESULT_FAILURE;
            }

            break;

        case SEC_KEYTYPE_ECC_NISTP256:
            if (SecCertificate_ExtractECCPublicKey(certificateHandle, &ecc_public_key) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecCertificate_ExtractECCPublicKey failed");
                return SEC_RESULT_FAILURE;
            }

            if (SecKey_Provision(processorHandle, SEC_OBJECTID_SIG_FROM_CERT, SEC_STORAGELOC_RAM_SOFT_WRAPPED,
                        SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC, (SEC_BYTE*) &ecc_public_key,
                        sizeof(ecc_public_key)) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                return SEC_RESULT_FAILURE;
            }

            break;

        default:
            SEC_LOG_ERROR("SecSignature_SingleInputCert: Unhandled keyType %d", (int) key_type);
            return SEC_RESULT_FAILURE;
    }

    if (SecKey_GetInstance(processorHandle, SEC_OBJECTID_SIG_FROM_CERT, &keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_Result result = SecSignature_SingleInput(processorHandle, algorithm, mode, keyHandle, input, inputSize,
            signature, signatureSize);
    SecKey_Release(keyHandle);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecSignature_SingleInputId(Sec_ProcessorHandle* processorHandle, Sec_SignatureAlgorithm algorithm,
        Sec_SignatureMode mode, SEC_OBJECTID id, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE* signatureSize) {
    Sec_KeyHandle* keyHandle = NULL;

    if (SecKey_GetInstance(processorHandle, id, &keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_Result result = SecSignature_SingleInput(processorHandle, algorithm, mode, keyHandle, input, inputSize,
            signature, signatureSize);
    SecKey_Release(keyHandle);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecSignature_SingleInputCertId(Sec_ProcessorHandle* processorHandle, Sec_SignatureAlgorithm algorithm,
        Sec_SignatureMode mode, SEC_OBJECTID cert_id, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE* signatureSize) {
    Sec_CertificateHandle* certificateHandle = NULL;

    if (SecCertificate_GetInstance(processorHandle, cert_id, &certificateHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_Result result = SecSignature_SingleInputCert(processorHandle, algorithm, mode, certificateHandle, input,
            inputSize, signature, signatureSize);
    SecCertificate_Release(certificateHandle);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Check if provided algorithm takes digest as an input.
 */
SEC_BOOL SecSignature_IsDigest(Sec_SignatureAlgorithm alg) {
    return alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST ||
           alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST ||
           alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST;
}

SEC_BOOL SecSignature_IsRsaPss(Sec_SignatureAlgorithm alg) {
    return alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS ||
           alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST;
}

static Sec_KeyContainer get_rsa_public_key_container_for_byte_length(SEC_BYTE* numBytes) {
    switch (Sec_BEBytesToUint32(numBytes)) {
        case 128:
            return SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC;

        case 256:
            return SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC;

        case 384:
            return SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC;

        default:
            SEC_LOG_ERROR("Invalid numBytes encountered: %d", numBytes);
            return SEC_KEYCONTAINER_NUM;
    }
}
