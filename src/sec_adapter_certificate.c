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
#include "sec_security_utils.h"
#include <memory.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define CERTIFICATE_BUFFER_SIZE (1024 * 64)

struct Sec_CertificateHandle_struct {
    Sec_ProcessorHandle* processorHandle;
    SEC_OBJECTID object_id;
    Sec_StorageLoc location;
    Sec_CertificateData cert_data;
};

static void Sec_FindRAMCertificateData(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_RAMCertificateData** data, Sec_RAMCertificateData** parent) {
    *parent = NULL;
    *data = processorHandle->ram_certs;

    while ((*data) != NULL) {
        if (object_id == (*data)->object_id)
            return;

        *parent = (*data);
        *data = (*data)->next;
    }

    *parent = NULL;
}

static Sec_Result Sec_RetrieveCertificateData(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc* location, Sec_CertificateData* certData) {
    char file_name_cert[SEC_MAX_FILE_PATH_LEN];
    char file_name_info[SEC_MAX_FILE_PATH_LEN];
    char file_name_verification[SEC_MAX_FILE_PATH_LEN];
    Sec_RAMCertificateData* ram_cert = NULL;
    Sec_RAMCertificateData* ram_cert_parent = NULL;
    SEC_SIZE data_read;

    CHECK_PROCHANDLE(processorHandle)

    /* check in RAM */
    Sec_FindRAMCertificateData(processorHandle, object_id, &ram_cert, &ram_cert_parent);
    if (ram_cert != NULL) {
        memcpy(certData, &(ram_cert->cert_data), sizeof(Sec_CertificateData));
        *location = SEC_STORAGELOC_RAM;
        return SEC_RESULT_SUCCESS;
    }

    /* check in app dir */
    char* sec_dirs[] = {processorHandle->app_dir, processorHandle->global_dir};
    for (int i = 0; i < 2; i++) {
        if (sec_dirs[i] != NULL) {
            snprintf(file_name_cert, sizeof(file_name_cert), "%s" SEC_CERT_FILENAME_PATTERN, sec_dirs[i],
                    object_id);
            snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_CERTINFO_FILENAME_PATTERN, sec_dirs[i],
                    object_id);
            snprintf(file_name_verification, sizeof(file_name_verification), "%s" SEC_VERIFICATION_FILENAME_PATTERN,
                    sec_dirs[i], object_id);
            if (SecUtils_FileExists(file_name_cert) && SecUtils_FileExists(file_name_info)) {
                if (SecUtils_ReadFile(file_name_cert, certData->cert, sizeof(certData->cert), &certData->cert_len) !=
                                SEC_RESULT_SUCCESS ||
                        SecUtils_ReadFile(file_name_info, certData->mac, sizeof(certData->mac), &data_read) !=
                                SEC_RESULT_SUCCESS) {
                    SEC_LOG_ERROR("Could not read one of the certificate files");
                    return SEC_RESULT_FAILURE;
                }

                if (data_read != sizeof(certData->mac)) {
                    SEC_LOG_ERROR("File is not of the correct size");
                    return SEC_RESULT_FAILURE;
                }

                if (SecUtils_FileExists(file_name_verification)) {
                    if (verify_verification_file(processorHandle, file_name_verification, certData->cert,
                                certData->cert_len, certData->mac, sizeof(certData->mac)) != SEC_RESULT_SUCCESS) {
                        SEC_LOG_ERROR("Certificate verification failed");
                        return SEC_RESULT_FAILURE;
                    }
                } else {
                    // If sha file doesn't exist, the bundle file was created by an old SecApi. Just create the
                    // verification file.
                    if (write_verification_file(processorHandle, file_name_verification, certData->cert,
                                certData->cert_len, certData->mac, sizeof(certData->mac)) != SEC_RESULT_SUCCESS) {
                        SEC_LOG_ERROR("Could not write SHA file");
                    }
                }

                *location = SEC_STORAGELOC_FILE;
                return SEC_RESULT_SUCCESS;
            }
        }
    }

    return SEC_RESULT_NO_SUCH_ITEM;
}

static Sec_Result Sec_SignCertificateData(Sec_ProcessorHandle* processorHandle, Sec_CertificateData* cert_store) {
    SEC_SIZE mac_size;

    CHECK_PROCHANDLE(processorHandle)

    if (SecMac_SingleInputId(processorHandle, SEC_MACALGORITHM_HMAC_SHA256, SEC_OBJECTID_CERTSTORE_KEY,
                cert_store->cert, cert_store->cert_len, cert_store->mac, &mac_size) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecMac_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result Sec_ValidateCertificateData(Sec_ProcessorHandle* processorHandle, Sec_CertificateData* cert_store) {
    SEC_BYTE mac_buffer[SEC_MAC_MAX_LEN];
    SEC_SIZE mac_size = 0;

    CHECK_PROCHANDLE(processorHandle)

    if (SecMac_SingleInputId(processorHandle, SEC_MACALGORITHM_HMAC_SHA256, SEC_OBJECTID_CERTSTORE_KEY,
                cert_store->cert, cert_store->cert_len, mac_buffer, &mac_size) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecMac_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    if (Sec_Memcmp(mac_buffer, cert_store->mac, mac_size) != 0) {
        SEC_LOG_ERROR("Certificate mac does not match the expected value");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result Sec_ProcessCertificateContainer(Sec_ProcessorHandle* processorHandle, Sec_CertificateData* cert_data,
        Sec_CertificateContainer data_type, void* data, SEC_SIZE data_len) {
    BIO* bio = NULL;
    X509* x509 = NULL;

    if (data_type == SEC_CERTIFICATECONTAINER_X509_DER) {
        Sec_RSARawPublicKey pub_rsa;
        Sec_ECCRawPublicKey pub_ecc;
        if (Pubops_ExtractRSAPubFromX509Der(data, data_len, &pub_rsa) != SEC_RESULT_SUCCESS &&
                Pubops_ExtractECCPubFromX509Der(data, data_len, &pub_ecc) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Pubops_ExtractECCPubFromX509Der failed");
            return SEC_RESULT_FAILURE;
        }

        memset(cert_data, 0, sizeof(Sec_CertificateData));
        memcpy(cert_data->cert, data, data_len);
        cert_data->cert_len = data_len;
        return Sec_SignCertificateData(processorHandle, cert_data);
    }

    if (data_type == SEC_CERTIFICATECONTAINER_X509_PEM) {
        bio = BIO_new_mem_buf(data, (int) data_len);
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        SEC_BIO_FREE(bio);
        bio = NULL;

        if (x509 == NULL) {
            SEC_X509_FREE(x509);
            SEC_LOG_ERROR("Invalid X509 key container");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        memset(cert_data, 0, sizeof(Sec_CertificateData));
        cert_data->cert_len = SecUtils_X509ToDerLen(x509, cert_data->cert, sizeof(cert_data->cert));
        if (cert_data->cert_len == 0) {
            SEC_X509_FREE(x509);
            SEC_LOG_ERROR("Certificate is too large");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        SEC_X509_FREE(x509);
        return Sec_SignCertificateData(processorHandle, cert_data);
    }

    SEC_LOG_ERROR("Unimplemented certificate container type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

static Sec_Result Sec_StoreCertificateData(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc location, Sec_CertificateData* certData) {
    Sec_RAMCertificateData* ram_cert;

    if (location == SEC_STORAGELOC_RAM) {
        SecCertificate_Delete(processorHandle, object_id);

        ram_cert = calloc(1, sizeof(Sec_RAMCertificateData));
        if (ram_cert == NULL) {
            SEC_LOG_ERROR("Malloc failed");
            return SEC_RESULT_FAILURE;
        }
        ram_cert->object_id = object_id;
        memcpy(&(ram_cert->cert_data), certData, sizeof(Sec_CertificateData));
        ram_cert->next = processorHandle->ram_certs;
        processorHandle->ram_certs = ram_cert;

        return SEC_RESULT_SUCCESS;
    }

    if (location == SEC_STORAGELOC_FILE) {
        if (processorHandle->app_dir == NULL) {
            SEC_LOG_ERROR("Cannot write file because app_dir is NULL");
            return SEC_RESULT_FAILURE;
        }

        SecCertificate_Delete(processorHandle, object_id);

        char file_name_cert[SEC_MAX_FILE_PATH_LEN];
        char file_name_info[SEC_MAX_FILE_PATH_LEN];
        char file_name_verification[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_cert, sizeof(file_name_cert), "%s" SEC_CERT_FILENAME_PATTERN, processorHandle->app_dir,
                object_id);
        snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_CERTINFO_FILENAME_PATTERN, processorHandle->app_dir,
                object_id);
        snprintf(file_name_verification, sizeof(file_name_verification), "%s" SEC_VERIFICATION_FILENAME_PATTERN,
                processorHandle->app_dir, object_id);

        if (SecUtils_WriteFile(file_name_cert, certData->cert, certData->cert_len) != SEC_RESULT_SUCCESS ||
                SecUtils_WriteFile(file_name_info, certData->mac, sizeof(certData->mac)) != SEC_RESULT_SUCCESS ||
                write_verification_file(processorHandle, file_name_verification, certData->cert, certData->cert_len,
                        certData->mac, sizeof(certData->mac)) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Could not write one of the cert files");
            SecUtils_RmFile(file_name_cert);
            SecUtils_RmFile(file_name_info);
            SecUtils_RmFile(file_name_verification);
            return SEC_RESULT_FAILURE;
        }

        return SEC_RESULT_SUCCESS;
    }

    SEC_LOG_ERROR("Unimplemented location type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

/**
 * @brief Obtain a handle to the provisioned certificate.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the certificate.
 * @param certHandle output certificate handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_GetInstance(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_CertificateHandle** certHandle) {
    Sec_Result result;
    Sec_StorageLoc location;

    *certHandle = NULL;
    CHECK_PROCHANDLE(processorHandle)

    if (object_id == SEC_OBJECTID_INVALID) {
        SEC_LOG_ERROR("Invalid object_id");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    *certHandle = calloc(1, sizeof(Sec_CertificateHandle));
    if (*certHandle == NULL) {
        SEC_LOG_ERROR("Calloc failed");
        return SEC_RESULT_FAILURE;
    }

    result = Sec_RetrieveCertificateData(processorHandle, object_id, &location, &(*certHandle)->cert_data);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_FREE(*certHandle);
        return result;
    }

    result = Sec_ValidateCertificateData(processorHandle, &(*certHandle)->cert_data);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("_Sec_ValidateCertificateData failed");
        SEC_FREE(*certHandle);
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    (*certHandle)->object_id = object_id;
    (*certHandle)->location = location;
    (*certHandle)->processorHandle = processorHandle;

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Provision a certificate onto the system.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the certificate to provision.
 * @param location location where the certificate should be provisioned to.
 * @param data_type container type for the input certificate data.
 * @param data pointer to certificate container data.
 * @param data_len certificate container data length.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_Provision(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc location, Sec_CertificateContainer data_type, SEC_BYTE* data, SEC_SIZE data_len) {
    Sec_CertificateData* cert_data;
    Sec_Result result;

    CHECK_PROCHANDLE(processorHandle)

    if (object_id == SEC_OBJECTID_INVALID) {
        SEC_LOG_ERROR("Cannot provision object with SEC_OBJECTID_INVALID");
        return SEC_RESULT_FAILURE;
    }

    if (data == NULL) {
        SEC_LOG_ERROR("NULL data");
        return SEC_RESULT_FAILURE;
    }

    if (data_len > SEC_CERT_MAX_DATA_LEN) {
        SEC_LOG_ERROR("Input certificate is too large");
        return SEC_RESULT_FAILURE;
    }

    cert_data = calloc(1, sizeof(Sec_CertificateData));
    if (cert_data == NULL) {
        SEC_LOG_ERROR("calloc failed");
        return SEC_RESULT_FAILURE;
    }

    result = Sec_ProcessCertificateContainer(processorHandle, cert_data, data_type, data, data_len);
    if (result != SEC_RESULT_SUCCESS) {
        SEC_FREE(cert_data);
        return result;
    }

    result = Sec_StoreCertificateData(processorHandle, object_id, location, cert_data);
    SEC_FREE(cert_data);
    return result;
}

/**
 * @brief Delete the specified certificate from the system.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the certificate to delete.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_Delete(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id) {
    Sec_RAMCertificateData* ram_cert = NULL;
    Sec_RAMCertificateData* ram_cert_parent = NULL;
    SEC_SIZE certs_found = 0;
    SEC_SIZE certs_deleted = 0;

    CHECK_PROCHANDLE(processorHandle)

    /* ram */
    Sec_FindRAMCertificateData(processorHandle, object_id, &ram_cert, &ram_cert_parent);
    if (ram_cert != NULL) {
        if (ram_cert_parent == NULL)
            processorHandle->ram_certs = ram_cert->next;
        else
            ram_cert_parent->next = ram_cert->next;

        Sec_Memset(ram_cert, 0, sizeof(Sec_RAMCertificateData));

        SEC_FREE(ram_cert);

        ++certs_found;
        ++certs_deleted;
    }

    /* app_dir */
    if (processorHandle->app_dir != NULL) {
        char file_name[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name, sizeof(file_name), "%s" SEC_CERT_FILENAME_PATTERN, processorHandle->app_dir, object_id);
        if (SecUtils_FileExists(file_name)) {
            SecUtils_RmFile(file_name);
            ++certs_found;

            if (!SecUtils_FileExists(file_name))
                ++certs_deleted;
        }

        char file_name_info[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_CERTINFO_FILENAME_PATTERN, processorHandle->app_dir,
                object_id);
        if (!SecUtils_FileExists(file_name) && SecUtils_FileExists(file_name_info)) {
            SecUtils_RmFile(file_name_info);
        }

        char file_name_verification[SEC_MAX_FILE_PATH_LEN];
        snprintf(file_name_verification, sizeof(file_name_verification), "%s" SEC_VERIFICATION_FILENAME_PATTERN,
                processorHandle->app_dir, object_id);
        if (!SecUtils_FileExists(file_name) && SecUtils_FileExists(file_name_verification))
            SecUtils_RmFile(file_name_verification);
    }

    if (certs_found == 0)
        return SEC_RESULT_NO_SUCH_ITEM;

    if (certs_found != certs_deleted)
        return SEC_RESULT_ITEM_NON_REMOVABLE;

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Extract the RSA public key information from the certificate.
 *
 * @param certificateHandle certificate handle.
 * @param public_key pointer to the output structure that will be filled with
 * public key data.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_ExtractRSAPublicKey(Sec_CertificateHandle* certificateHandle,
        Sec_RSARawPublicKey* public_key) {
    CHECK_HANDLE(certificateHandle)

    if (Pubops_ExtractRSAPubFromX509Der(certificateHandle->cert_data.cert, certificateHandle->cert_data.cert_len,
                public_key) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_ExtractRSAPubFromX509Der failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Extract the ECC public key information from the certificate.
 *
 * @param certificateHandle certificate handle.
 * @param public_key pointer to the output structure that will be filled with
 * public key data.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_ExtractECCPublicKey(Sec_CertificateHandle* certificateHandle,
        Sec_ECCRawPublicKey* public_key) {
    CHECK_HANDLE(certificateHandle)

    if (Pubops_ExtractECCPubFromX509Der(certificateHandle->cert_data.cert, certificateHandle->cert_data.cert_len,
                public_key) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_ExtractECCPubFromX509Der failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Verify certificate signature.
 *
 * @param certificateHandle certificate handle.
 * @param keyHandle handle of the private key used for signing or it's corresponding
 * public key.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_Verify(Sec_CertificateHandle* certificateHandle, Sec_KeyHandle* keyHandle) {
    Sec_RSARawPublicKey rsa_public_key;
    Sec_ECCRawPublicKey ecc_public_key;
    Sec_Result result = SEC_RESULT_FAILURE;

    CHECK_HANDLE(certificateHandle)
    CHECK_HANDLE(keyHandle)

    switch (SecKey_GetKeyType(keyHandle)) {
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
        case SEC_KEYTYPE_RSA_3072:
        case SEC_KEYTYPE_RSA_3072_PUBLIC:
            if (SecKey_ExtractRSAPublicKey(keyHandle, &rsa_public_key) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecKey_ExtractRSAPublicKey failed");
                break;
            }

            result = SecCertificate_VerifyWithRawRSAPublicKey(certificateHandle, &rsa_public_key);
            break;

        case SEC_KEYTYPE_ECC_NISTP256:
        case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
            if (SecKey_ExtractECCPublicKey(keyHandle, &ecc_public_key) != SEC_RESULT_SUCCESS) {
                SEC_LOG_ERROR("SecKey_ExtractECCPublicKey failed");
                break;
            }

            result = SecCertificate_VerifyWithRawECCPublicKey(certificateHandle, &ecc_public_key);
            break;

        default:
            break; // defaults to FAILURE
    }

    return result;
}

/**
 * @brief Verify certificate signature.
 *
 * @param certificateHandle certificate handle.
 * @param public_key structure holding the public key information.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_VerifyWithRawRSAPublicKey(Sec_CertificateHandle* certificateHandle,
        Sec_RSARawPublicKey* public_key) {
    CHECK_HANDLE(certificateHandle)
    if (public_key == NULL) {
        SEC_LOG_ERROR("NULL public_key");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (Pubops_VerifyX509WithPubRsa(certificateHandle->cert_data.cert, certificateHandle->cert_data.cert_len,
                public_key) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Pubops_VerifyX509WithPubRsa failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Verify certificate signature - ECC.
 *
 * @param certificateHandle certificate handle.
 * @param public_key structure holding the public key information.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_VerifyWithRawECCPublicKey(Sec_CertificateHandle* certificateHandle,
        Sec_ECCRawPublicKey* public_key) {
    CHECK_HANDLE(certificateHandle)
    if (public_key == NULL) {
        SEC_LOG_ERROR("NULL public_key");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    if (Pubops_VerifyX509WithPubEcc(certificateHandle->cert_data.cert, certificateHandle->cert_data.cert_len,
                public_key) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Pubops_VerifyX509WithPubEcc failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Obtain the certificate data in clear text DER format.
 *
 * @param certificateHandle certificate handle.
 * @param buffer pointer to the output buffer that will be filled with certificate data.
 * @param buffer_len the length of the output buffer.
 * @param written pointer to the output value specifying the number of bytes written to the
 * output buffer.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_Export(Sec_CertificateHandle* certificateHandle, SEC_BYTE* buffer, SEC_SIZE buffer_len,
        SEC_SIZE* written) {
    CHECK_HANDLE(certificateHandle)

    if (buffer == NULL) {
        *written = certificateHandle->cert_data.cert_len;
        return SEC_RESULT_SUCCESS;
    }

    if (buffer_len < certificateHandle->cert_data.cert_len)
        return SEC_RESULT_BUFFER_TOO_SMALL;

    memcpy(buffer, certificateHandle->cert_data.cert, certificateHandle->cert_data.cert_len);
    *written = certificateHandle->cert_data.cert_len;
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Release the certificate object.
 *
 * @param certificateHandle certificate handle.
 *
 * @return The status of the operation.
 */
Sec_Result SecCertificate_Release(Sec_CertificateHandle* certificateHandle) {
    CHECK_HANDLE(certificateHandle)
    SEC_FREE(certificateHandle);
    return SEC_RESULT_SUCCESS;
}

/**
 * @brief Obtain a list of all provisioned items.  At most maxNumItems will be written to the output buffer.
 *
 * @param proc Secure processor handle.
 * @param items buffer that the found item ids will be stored in.
 * @param maxNumItems maximum number of items that can be written to the output buffer.
 *
 * @return number of items written.
 */
SEC_SIZE SecCertificate_List(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID* items, SEC_SIZE maxNumItems) {
    Sec_RAMCertificateData* cert;
    SEC_SIZE num_items = 0;

    CHECK_PROCHANDLE(processorHandle)

    /* look in RAM */
    cert = processorHandle->ram_certs;
    while (cert != NULL) {
        num_items = SecUtils_UpdateItemList(items, maxNumItems, num_items, cert->object_id);
        cert = cert->next;
    }

    /* look in file system */
    if (processorHandle->global_dir != NULL) {
        num_items = SecUtils_UpdateItemListFromDir(items, maxNumItems, num_items, processorHandle->global_dir,
                SEC_CERT_FILENAME_EXT);
    }

    if (processorHandle->app_dir != NULL) {
        num_items = SecUtils_UpdateItemListFromDir(items, maxNumItems, num_items, processorHandle->app_dir,
                SEC_CERT_FILENAME_EXT);
    }

    return num_items;
}

X509* SecCertificate_DerToX509(void* mem, SEC_SIZE len) {
    X509* x509 = NULL;
    const SEC_BYTE* ptr = (const SEC_BYTE*) mem;
    x509 = d2i_X509(&x509, &ptr, len);
    return x509;
}

Sec_KeyType SecCertificate_GetKeyType(Sec_CertificateHandle* certificateHandle) {
    Sec_RSARawPublicKey pub_rsa;
    if (Pubops_ExtractRSAPubFromX509Der(certificateHandle->cert_data.cert, certificateHandle->cert_data.cert_len,
                &pub_rsa) == SEC_RESULT_SUCCESS) {
        switch (Sec_BEBytesToUint32(pub_rsa.modulus_len_be)) {
            case 128:
                return SEC_KEYTYPE_RSA_1024_PUBLIC;

            case 256:
                return SEC_KEYTYPE_RSA_2048_PUBLIC;

            case 384:
                return SEC_KEYTYPE_RSA_3072_PUBLIC;

            default:
                SEC_LOG_ERROR("Invalid RSA modulus size encountered: %d", Sec_BEBytesToUint32(pub_rsa.modulus_len_be));
                return SEC_KEYTYPE_NUM;
        }
    }

    Sec_ECCRawPublicKey pub_ecc;
    if (Pubops_ExtractECCPubFromX509Der(certificateHandle->cert_data.cert, certificateHandle->cert_data.cert_len,
                &pub_ecc) == SEC_RESULT_SUCCESS) {
        return SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
    }

    SEC_LOG_ERROR("Could not find valid pub key in the certificate");
    return SEC_KEYTYPE_NUM;
}

/**
 * @brief Obtain an OpenSSL X509 certificate from the Security API cert handle.
 */
X509* SecCertificate_ToX509(Sec_CertificateHandle* certificateHandle) {
    SEC_BYTE exported_cert[CERTIFICATE_BUFFER_SIZE];
    SEC_SIZE exported_cert_len;

    if (SecCertificate_Export(certificateHandle, exported_cert, sizeof(exported_cert), &exported_cert_len) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_Export failed");
        return NULL;
    }

    return SecCertificate_DerToX509(exported_cert, exported_cert_len);
}

/**
 * @brief Find if the certificate with a specific id has been provisioned.
 *
 * @param processorHandle secure processor handle.
 * @param object_id id of the certificate.
 *
 * @return 1 if an object has been provisioned, 0 if it has not been.
 */
SEC_BOOL SecCertificate_IsProvisioned(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id) {
    Sec_CertificateHandle* certificateHandle;

    if (SecCertificate_GetInstance(processorHandle, object_id, &certificateHandle) != SEC_RESULT_SUCCESS) {
        return SEC_FALSE;
    }

    SecCertificate_Release(certificateHandle);
    return SEC_TRUE;
}

/**
 * @brief Obtain the size of the certificate in DER format.
 *
 * @param certificateHandle certificate whose size we want to obtain.
 */
SEC_SIZE SecCertificate_GetSize(Sec_CertificateHandle* certificateHandle) {
    SEC_BYTE buffer[SEC_CERT_MAX_DATA_LEN];
    SEC_SIZE written;

    if (SecCertificate_Export(certificateHandle, buffer, sizeof(buffer), &written) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCertificate_Export failed");
        return 0;
    }

    return written;
}

/**
 * @brief finds the first available certificate id in the range passed in.
 *
 * @param proc secure processor.
 * @param base bottom of the range to search.
 * @param top top of the range to search.
 * @return
 */
SEC_OBJECTID SecCertificate_ObtainFreeObjectId(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID base,
        SEC_OBJECTID top) {
    SEC_OBJECTID id;
    Sec_CertificateHandle* certificateHandle;
    Sec_Result result;

    for (id = base; id < top; ++id) {
        result = SecCertificate_GetInstance(processorHandle, id, &certificateHandle);

        if (result == SEC_RESULT_SUCCESS)
            SecCertificate_Release(certificateHandle);
        else
            return id;
    }

    return SEC_OBJECTID_INVALID;
}
