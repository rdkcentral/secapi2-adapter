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

#ifndef SEC_SECURITY_H_
#define SEC_SECURITY_H_

#include "sec_security_common.h"
#include "sec_security_datatype.h"
#if !defined(SEC_TARGET_IOS) && !defined(SEC_TARGET_TVOS)
#include <sys/syscall.h>
#endif
#include <unistd.h>

#ifdef __cplusplus
#include <cstdio>
extern "C" {
#else
#include <stdio.h>
#endif

#define OPENSSL_SUCCESS 1

#define SEC_KEYSTORAGE_FILE_DEFAULT_DIR "/opt/drm"
#define SEC_CERTIFICATESTORAGE_FILE_DEFAULT_DIR "/opt/drm"
#define SEC_BUNDLESTORAGE_FILE_DEFAULT_DIR "/opt/drm"

/* macro to string */
#define SEC_MTOS_(x) #x
#define SEC_MTOS(x) SEC_MTOS_(x)

/* min */
#ifndef SEC_MIN
#define SEC_MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/* max */
#ifndef SEC_MAX
#define SEC_MAX(a, b) (((a) < (b)) ? (b) : (a))
#endif

#define SEC_FREE(x) \
    do { \
        if ((x) != NULL) { \
            free(x); \
            (x) = NULL; \
        } \
    } while (0)
#define SEC_RSA_FREE(x) \
    do { \
        if ((x) != NULL) { \
            RSA_free(x); \
            (x) = NULL; \
        } \
    } while (0)
#define SEC_ECC_FREE(x) \
    do { \
        if ((x) != NULL) { \
            EC_KEY_free(x); \
            (x) = NULL; \
        } \
    } while (0)
#define SEC_EVPPKEY_FREE(x) \
    do { \
        if ((x) != NULL) { \
            EVP_PKEY_free(x); \
            (x) = NULL; \
        } \
    } while (0)
#define SEC_BIO_FREE(x) \
    do { \
        if ((x) != NULL) { \
            BIO_free(x); \
            (x) = NULL; \
        } \
    } while (0)
#define SEC_X509_FREE(x) \
    do { \
        if ((x) != NULL) { \
            X509_free(x); \
            (x) = NULL; \
        } \
    } while (0)

/* debug prints */
#define SEC_PRINT(fmt, ...) \
    do { \
        if (Sec_GetLogger() != NULL) { \
            Sec_GetLogger()(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#if defined(SEC_TARGET_IOS) || defined(SEC_TARGET_TVOS)
#define SEC_LOG(txt, ...) \
    do { \
        SEC_PRINT("" txt " (%s, %s, line %d)\n", ##__VA_ARGS__, __PRETTY_FUNCTION__, __FILE__, __LINE__); \
    } while (0)
#else
#define SEC_LOG(txt, ...) \
    do { \
        SEC_PRINT("[%ld] " txt " (%s, %s, line %d)\n", (long int) syscall(SYS_gettid), ##__VA_ARGS__, \
                __PRETTY_FUNCTION__, __FILE__, __LINE__); \
    } while (0)
#endif

#define SEC_LOG_ERROR(txt, ...) \
    do { \
        SEC_LOG("ERROR: " txt, ##__VA_ARGS__); \
    } while (0)

#define SEC_TRACE(enabled, txt, ...) \
    do { \
        if (enabled) { \
            SEC_LOG(#enabled ": " txt, ##__VA_ARGS__); \
        } \
    } while (0)

/**
 * @brief Initialize secure processor
 *
 * Initializes the secure processor, generates key derivation base key,
 * sets up all required resources.  Only one secure processor can be
 * active at a time.
 *
 * @param processorHandle pointer to a processor handle that will be set to
 * a constructed handle.
 * @param socInitParams pointer to initialization information for the secure
 * processor.  This structure is implementation specific.
 *
 * @return The status of the operation
 */
Sec_Result SecProcessor_GetInstance(Sec_ProcessorHandle** processorHandle,
        Sec_ProcessorInitParams* socInitParams);

/**
 * @brief Initialize secure processor
 *
 * Initializes the secure processor, generates key derivation base key,
 * sets up all required resources.  Only one secure processor can be
 * active at a time.
 *
 * @param processorHandle pointer to a processor handle that will be set to
 * a constructed handle.
 * @param globalDir path to the read only object directory.  Can be set to NULL.
 * @param appDir path to the read/write object directory.  Can be set to NULL.
 *
 * @return The status of the operation
 */
Sec_Result SecProcessor_GetInstance_Directories(Sec_ProcessorHandle** processorHandle, const char* globalDir,
        const char* appDir);

/**
 * @brief Get the minimum depth of the hardware key ladder
 *
 * @param handle pointer to a handle
 * @param root root key type
 *
 * @return The key ladder depth
 */
SEC_SIZE SecProcessor_GetKeyLadderMinDepth(Sec_ProcessorHandle* processorHandle, Sec_KeyLadderRoot root);

/**
 * @brief Get the maximum depth of the hardware key ladder
 *
 * @param handle pointer to a handle
 * @param root root key type
 *
 * @return The key ladder depth
 */
SEC_SIZE SecProcessor_GetKeyLadderMaxDepth(Sec_ProcessorHandle* processorHandle, Sec_KeyLadderRoot root);

/**
 * @brief Prints SOC specific version info
 *
 * @param processorHandle secure processor handle
 */
Sec_Result SecProcessor_PrintInfo(Sec_ProcessorHandle* processorHandle);

/**
 * @brief Get the Security Processor information (SecAPI version and build
 * information).
 *
 * @param processorHandle secure processor handle
 * @param pointer to secure processor information
 */
Sec_Result SecProcessor_GetInfo(Sec_ProcessorHandle* processorHandle, Sec_ProcessorInfo* secProcInfo);

/**
 * @brief Obtain the device id
 *
 * @param processorHandle secure processor handle
 * @param deviceId pointer to a buffer that is SEC_DEVICEID_LEN long.  The
 * buffer will be filled with a device id.
 *
 * @return The status of the operation
 */
Sec_Result SecProcessor_GetDeviceId(Sec_ProcessorHandle* processorHandle, SEC_BYTE* deviceId);

/**
 * @brief Release the security processor
 *
 * @param processorHandle secure processor handle
 *
 * @return The status of the operation
 */
Sec_Result SecProcessor_Release(Sec_ProcessorHandle* processorHandle);

/**
 * @brief Initialize cipher object
 *
 * @param processorHandle secure processor handle
 * @param algorithm cipher algorithm to use
 * @param mode cipher mode to use
 * @param keyHandle handle to use
 * @param iv initialization vector value.  Can be set to NULL is the cipher
 * algorithm chosen does not require it.
 * @param cipherHandle pointer to a cipher handle that will be set once
 * the cipher object is constructed
 *
 * @return The status of the operation
 */
Sec_Result SecCipher_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_CipherAlgorithm algorithm,
        Sec_CipherMode mode, Sec_KeyHandle* keyHandle, SEC_BYTE* iv, Sec_CipherHandle** cipherHandle);

/**
 * @brief Update the IV on the cipher handle
 */
Sec_Result SecCipher_UpdateIV(Sec_CipherHandle* cipherHandle, SEC_BYTE* iv);

/**
 * @brief En/De-cipher specified input data into and output buffer
 *
 * @param cipherHandle cipher handle
 * @param input pointer to input data
 * @param inputSize the length of input data in bytes
 * @param lastInput boolean value specifying whether this is the last chunk
 * of input that will be processed.
 * @param output pointer to output data buffer
 * @param outputSize the size of the output buffer
 * @param bytesWritten pointer to a value that will be set to number
 * of bytes written to the output buffer
 *
 * @return The status of the operation
 */
Sec_Result SecCipher_Process(Sec_CipherHandle* cipherHandle, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BOOL lastInput,
        SEC_BYTE* output, SEC_SIZE outputSize, SEC_SIZE* bytesWritten);

/**
 * @brief En/De-cipher specified fragmented input data into and output buffer
 *
 * @param cipherHandle cipher handle
 * @param input pointer to input data
 * @param inputSize the length of input data in bytes
 * @param lastInput boolean value specifying whether this is the last chunk
 * of input that will be processed.
 * @param output pointer to output data buffer
 * @param outputSize the size of the output buffer
 * @param bytesWritten pointer to a value that will be set to number
 * of bytes written to the output buffer
 * @param framentOffset offset in bytes of the fragment data within larger packet
 * @param fragmentSize length in bytes of the data fragment
 * @param fragmentPeriod the length in bytes of the packet containing the fragment
 *
 * @return The status of the operation
 */
Sec_Result SecCipher_ProcessFragmented(Sec_CipherHandle* cipherHandle, SEC_BYTE* input, SEC_SIZE inputSize,
        SEC_BOOL lastInput, SEC_BYTE* output, SEC_SIZE outputSize, SEC_SIZE* bytesWritten, SEC_SIZE fragmentOffset,
        SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod);

/**
 * @brief Process the opaque buffers that were obtained with Sec_OpaqueBufferMalloc
 *
 * @param cipherHandle cipher handle
 * @param inputHandle opaque buffer containing input
 * @param outputHandle opaque buffer for writing output
 * @param inputSize the length of input to process
 * @param lastInput boolean value specifying whether this is the last chunk
 * of input that will be processed.
 * @param bytesWritten pointer to a value that will be set to number
 * of bytes written to the output buffer
 */
Sec_Result SecCipher_ProcessOpaque(Sec_CipherHandle* cipherHandle, Sec_OpaqueBufferHandle* inOpaqueBufferHandle,
        Sec_OpaqueBufferHandle* outOpaqueBufferHandle, SEC_SIZE inputSize, SEC_BOOL lastInput, SEC_SIZE* bytesWritten);

Sec_Result SecCipher_ProcessCtrWithOpaqueDataShift(Sec_CipherHandle* cipherHandle,
        Sec_OpaqueBufferHandle* inOpaqueBufferHandle, Sec_OpaqueBufferHandle* outOpaqueBufferHandle, SEC_SIZE inputSize,
        SEC_SIZE* bytesWritten, SEC_SIZE dataShift);

/**
 * @brief Perform cipher operation on the opaque input handle and check the output against the expected value.
 *
 * @param cipherHandle pointer to Sec_CipherHandle
 * @param opaqueBufferHandle pointer to opaque buffer containing input
 * @param SEC_SIZE checkLength number of bytes used for comparison
 * @param SEC_BYTE expected expected value used for comparison
 */
Sec_Result SecCipher_KeyCheckOpaque(Sec_CipherHandle* cipherHandle, Sec_OpaqueBufferHandle* opaqueBufferHandle,
        SEC_SIZE checkLength, SEC_BYTE* expected);
/**
 * @brief Release the cipher object
 *
 * @param cipherHandle cipher handle
 *
 * @return The status of the operation
 */
Sec_Result SecCipher_Release(Sec_CipherHandle* cipherHandle);

/**
 * @brief Obtain a digest object handle
 *
 * @param processorHandle secure processor handle
 * @param algorithm digest algorithm to use
 * @param digestHandle output digest object handle
 *
 * @return The status of the operation
 */
Sec_Result SecDigest_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_DigestAlgorithm algorithm,
        Sec_DigestHandle** digestHandle);

/**
 * @brief Update the digest value with the specified input
 *
 * @param digestHandle handle of the digest object
 * @param input pointer to the input buffer
 * @param inputSize size of the input buffer
 *
 * @return The status of the operation
 */
Sec_Result SecDigest_Update(Sec_DigestHandle* digestHandle, SEC_BYTE* input, SEC_SIZE inputSize);
/**
 * @brief Update the digest value with the key data
 *
 * @param digestHandle handle of the digest object
 * @param keyHandle key to use
 *
 * @return The status of the operation
 */
Sec_Result SecDigest_UpdateWithKey(Sec_DigestHandle* digestHandle, Sec_KeyHandle* keyHandle);

/**
 * @brief Calculate the resulting digest value and release the digest object
 *
 * @param digestHandle digest handle
 * @param digestOutput pointer to an output buffer that will be filled with the resulting
 * digest value.  Buffer should be SEC_DIGEST_MAX_LEN bytes long.
 * @param digestSize pointer to a value that will be set to actual size of the digest value
 *
 * @return The status of the operation
 */
Sec_Result SecDigest_Release(Sec_DigestHandle* digestHandle, SEC_BYTE* digestOutput, SEC_SIZE* digestSize);

/**
 * @brief Obtian a handle to the signature calculator
 *
 * @param processorHandle secure processor handle
 * @param algorithm signing algorithm
 * @param mode signing mode
 * @param keyHandle key used for signing operations
 * @param signatureHandle output signature handle
 *
 * @return The status of the operation
 */
Sec_Result SecSignature_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_SignatureAlgorithm algorithm,
        Sec_SignatureMode mode, Sec_KeyHandle* keyHandle, Sec_SignatureHandle** signatureHandle);

/**
 * @brief Sign/Verify Signature of the input data
 *
 * @param signatureHandle signature handle
 * @param input pointer to the input buffer whose signature we are generating/verifying
 * @param inputSize the length of the input
 * @param signature buffer where signature is/will be stored
 * @param signatureSize output variable that will be set to the signature size
 *
 * @return The status of the operation
 */
Sec_Result SecSignature_Process(Sec_SignatureHandle* signatureHandle, SEC_BYTE* input, SEC_SIZE inputSize,
        SEC_BYTE* signature, SEC_SIZE* signatureSize);

/**
 * @brief Release the signature object
 *
 * @param signatureHandle cipher handle
 *
 * @return The status of the operation
 */
Sec_Result SecSignature_Release(Sec_SignatureHandle* signatureHandle);

/**
 * @brief Obtain a handle for the MAC calculator
 *
 * @param processorHandle secure processor handle
 * @param algorithm MAC algorithm to use for MAC calculation
 * @param keyHandle key to use for the MAC calculation
 * @param macHandle output MAC calculator handle
 *
 * @return The status of the operation
 */
Sec_Result SecMac_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_MacAlgorithm algorithm,
        Sec_KeyHandle* keyHandle, Sec_MacHandle** macHandle);

/**
 * @brief Updates the digest value with the input data
 *
 * @param macHandle mac handle
 * @param input pointer to the input data
 * @param size of the input buffer
 *
 * @return The status of the operation
 */
Sec_Result SecMac_Update(Sec_MacHandle* macHandle, SEC_BYTE* input, SEC_SIZE inputSize);

/**
 * @brief Updates the digest value with the contents of a key
 *
 * @param macHandle mac handle
 * @param keyHandle key to use
 *
 * @return The status of the operation
 */
Sec_Result SecMac_UpdateWithKey(Sec_MacHandle* macHandle, Sec_KeyHandle* keyHandle);

/**
 * @brief Calculate the resulting MAC value and release the MAC object
 *
 * @param macHandle mac handle
 * @param macBuffer pointer to an output buffer that will be filled with the resulting
 * MAC value.  Buffer should be SEC_MAC_MAX_LEN bytes long.
 * @param macSize pointer to a value that will be set to actual size of the MAC value
 *
 * @return The status of the operation
 */
Sec_Result SecMac_Release(Sec_MacHandle* macHandle, SEC_BYTE* macBuffer, SEC_SIZE* macSize);

/**
 * @brief Obtain a handle to the random number generator
 *
 * @param processorHandle secure processor handle
 * @param algorithm random number algorithm to use
 * @param randomHandle output handle for the random number generator
 *
 * @return The status of the operation
 */
Sec_Result SecRandom_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_RandomAlgorithm algorithm,
        Sec_RandomHandle** randomHandle);

/**
 * @brief Generate random data
 *
 * @param randomHandle random number generator handle
 * @param output pointer to the output buffer where the random data will be stored
 * @param outpuSize the size of the output buffer
 *
 * @return The status of the operation
 */
Sec_Result SecRandom_Process(Sec_RandomHandle* randomHandle, SEC_BYTE* output, SEC_SIZE outputSize);

/**
 * @brief Release the random object
 *
 * @param randomHandle random handle
 *
 * @return The status of the operation
 */
Sec_Result SecRandom_Release(Sec_RandomHandle* randomHandle);

/**
 * @brief Obtain a handle to the provisioned certificate
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the certificate
 * @param certHandle output certificate handle
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_GetInstance(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_CertificateHandle** certHandle);

/**
 * @brief Provision a certificate onto the system
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the certificate to provision
 * @param location location where the certificate should be provisioned to
 * @param data_type container type for the input certificate data
 * @param data pointer to certificate container data
 * @param data_len certificate container data length
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Provision(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc location, Sec_CertificateContainer data_type, SEC_BYTE* data, SEC_SIZE data_len);

/**
 * @brief Delete the specified certificate from the system
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the certificate to delete
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Delete(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id);

/**
 * @brief Extract the RSA public key information from the certificate
 *
 * @param certificateHandle certificate handle
 * @param public_key pointer to the output structure that will be filled with
 * public key data
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_ExtractRSAPublicKey(Sec_CertificateHandle* certificateHandle,
        Sec_RSARawPublicKey* public_key);

/**
 * @brief Extract the ECC public key information from the certificate
 *
 * @param certificateHandle certificate handle
 * @param public_key pointer to the output structure that will be filled with
 * public key data
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_ExtractECCPublicKey(Sec_CertificateHandle* certificateHandle,
        Sec_ECCRawPublicKey* public_key);

/**
 * @brief Verify certificate signature
 *
 * @param certificateHandle certificate handle
 * @param key_handle handle of the private key used for signing or it's corresponding
 * public key
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Verify(Sec_CertificateHandle* certificateHandle, Sec_KeyHandle* keyHandle);

/**
 * @brief Verify certificate signature
 *
 * @param certificateHandle certificate handle
 * @param public_key structure holding the public key information
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_VerifyWithRawRSAPublicKey(Sec_CertificateHandle* certificateHandle,
        Sec_RSARawPublicKey* public_key);

/**
 * @brief Verify certificate signature - ECC
 *
 * @param certificateHandle certificate handle
 * @param public_key structure holding the public key information
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_VerifyWithRawECCPublicKey(Sec_CertificateHandle* certificateHandle,
        Sec_ECCRawPublicKey* public_key);

/**
 * @brief Obtain the certificate data in clear text DER format
 *
 * @param certificateHandle certificate handle
 * @param buffer pointer to the output buffer that will be filled with certificate data
 * @param buffer_len the length of the output buffer
 * @param written pointer to the output value specifying the number of bytes written to the
 * output buffer
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Export(Sec_CertificateHandle* certificateHandle, SEC_BYTE* buffer, SEC_SIZE buffer_len,
        SEC_SIZE* written);

/**
 * @brief Release the certificate object
 *
 * @param certificateHandle certificate handle
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Release(Sec_CertificateHandle* certificateHandle);

/**
 * @brief Obtain a list of all provisioned items.  At most maxNumItems will be written to the output buffer.
 *
 * @param proc Secure processor handle
 * @param items buffer that the found item ids will be stored in
 * @param maxNumItems maximum number of items that can be written to the output buffer
 *
 * @return number of items written
 */
SEC_SIZE SecCertificate_List(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID* items, SEC_SIZE maxNumItems);

/**
 * @brief Get the properties for the key handle.
 *
 * @param keyHandle pointer to Sec_KeyHandle
 * @param keyProps pointer to Sec_KeyProperties where information is stored.
 */
Sec_Result SecKey_GetKeyProperties(Sec_KeyHandle* keyHandle, Sec_KeyProperties* keyProps);

/**
 * @brief Get the length of the specified key in bytes
 *
 * In case of symmetric keys, the length returned is the actual size of the key data.
 * In case of asymmetric keys, the length returned is the size of the modulus in bytes.
 *
 * @param keyHandle key handle
 *
 * @return The status of the operation
 */
SEC_SIZE SecKey_GetKeyLen(Sec_KeyHandle* keyHandle);

/**
 * @brief Get the key type of the specified key handle
 *
 * @param keyHandle key handle
 *
 * @return The key type or SEC_KEYTYPE_NUM if the key handle is invalid
 */
Sec_KeyType SecKey_GetKeyType(Sec_KeyHandle* keyHandle);

/**
 * @brief Obtain a handle to a provisioned key
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the provisioned key that we are attempting to abtain
 * @param keyHandle pointer to the output key handle
 *
 * @return The status of the operation
 */
Sec_Result SecKey_GetInstance(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_KeyHandle** keyHandle);

/**
 * @brief Extract an RSA public key from a specified private key handle
 *
 * @param key_handle handle of the private key
 * @param public_key pointer to the output structure containing the public rsa key
 *
 * @return The status of the operation
 */
Sec_Result SecKey_ExtractRSAPublicKey(Sec_KeyHandle* keyHandle, Sec_RSARawPublicKey* public_key);

/**
 * @brief Extract an ECC public key from a specified private key handle
 *
 * @param key_handle handle of the private key
 * @param public_key pointer to the output structure containing the public ecc key
 *
 * @return The status of the operation
 */
Sec_Result SecKey_ExtractECCPublicKey(Sec_KeyHandle* keyHandle, Sec_ECCRawPublicKey* public_key);

/**
 * @brief Generate and provision a new key.
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the key to generate
 * @param keyType type of the key to generate
 * @param location location where the key should be stored
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Generate(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_KeyType keyType,
        Sec_StorageLoc location);

/**
 * @brief Provision a key
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the key to provision
 * @param location storage location where the key should be provisioned
 * @param data_type type of input key container that is being used
 * @param data pointer to the input key container
 * @param data_len the size of the input key container
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Provision(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_StorageLoc location,
        Sec_KeyContainer data_type, SEC_BYTE* data, SEC_SIZE data_len);

/**
 * @brief Derive and provision a key using the HKDF algorithm
 *
 * @param processorHandle secure processor handle
 * @param object_id_derived id of the key to provision
 * @param type_derived derived key type
 * @param loc_derived storage location where the derived key should be provisioned
 * @param macAlgorithm mac algorithm to use in the key derivation process
 * @param salt pointer to the salt value to use in key derivation process
 * @param saltSize the length of the salt buffer in bytes
 * @param info pointer to the info value to use in key derivation process
 * @param infoSize the length of the info buffer in bytes
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Derive_HKDF(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_KeyType type_derived, Sec_StorageLoc loc_derived, Sec_MacAlgorithm macAlgorithm, SEC_BYTE* nonce,
        SEC_BYTE* salt, SEC_SIZE saltSize, SEC_BYTE* info, SEC_SIZE infoSize);

/**
 * @brief Derive and provision a key using the Concat KDF algorithm
 *
 * @param processorHandle secure processor handle
 * @param object_id_derived id of the key to provision
 * @param type_derived derived key type
 * @param loc_derived storage location where the derived key should be provisioned
 * @param digestAlgorithm digest algorithm to use in the key derivation process
 * @param otherInfo pointer to the info value to use in key derivation process
 * @param otherInfoSize the length of the other info buffer in bytes
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Derive_ConcatKDF(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_KeyType type_derived, Sec_StorageLoc loc_derived, Sec_DigestAlgorithm digestAlgorithm, SEC_BYTE* nonce,
        SEC_BYTE* otherInfo, SEC_SIZE otherInfoSize);

/**
 * @brief Derive and provision an AES 128-bit key a vendor specific key ladder algorithm.
 *
 * This function will generate a key derived from one of the OTP keys.  The
 * result of this function may not be usable in Digest and Mac _UpdateWithKey
 * functions.  In general, this function will keep the derived key more secure
 * then the other SecKey_Derive functions because the key will not be accessable
 * by the host even during the generation time.
 *
 * @param processorHandle secure processor handle
 * @param object_id_derived id of the key to provision
 * @param loc_derived storage location where the derived key should be provisioned
 * @param input input buffer for the key derivation
 * @param input_len the length of the input buffer
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Derive_VendorAes128(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_StorageLoc loc_derived, SEC_BYTE* input, SEC_SIZE input_len);

/**
 * @brief Derive and provision an AES 128-bit key.
 *
 * This function will generate a key derived from one of the OTP keys.  The
 * result of this function may not be usable in Digest and Mac _UpdateWithKey
 * functions.  In general, this function will keep the derived key more secure
 * then the other SecKey_Derive functions because the key will not be accessable
 * by the host even during the generation time.
 *
 * @param processorHandle secure processor handle
 * @param object_id_derived id of the key to provision
 * @param type_derived derived key type
 * @param loc_derived storage location where the derived key should be provisioned
 * @param input1 16 byte input for stage 1 of the key ladder
 * @param input2 16 byte input for stage 2 of the key ladder
 * @param input3 16 byte input for stage 3 of the key ladder
 * @param input4 16 byte input for stage 4 of the key ladder
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Derive_KeyLadderAes128(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id_derived,
        Sec_StorageLoc loc_derived, Sec_KeyLadderRoot root, SEC_BYTE* input1, SEC_BYTE* input2, SEC_BYTE* input3,
        SEC_BYTE* input4);

Sec_Result SecKey_Derive_CMAC_AES128(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID idDerived,
        Sec_KeyType typeDerived, Sec_StorageLoc locDerived, SEC_OBJECTID derivationKey, SEC_BYTE* otherData,
        SEC_SIZE otherDataSize, SEC_BYTE* counter, SEC_SIZE counterSize);

/**
 * @brief Delete a provisioned key
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the key to delete
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Delete(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id);

/**
 * @brief Release the key object
 *
 * @param keyHandle key handle to release
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Release(Sec_KeyHandle* keyHandle);

/**
 * @brief Obtain a digest value computed over the base key contents
 *
 * @param processorHandle secure processor handle
 * @param nonce client nonce
 * @param alg digest algorithm
 * @param digest output digest value
 * @param digest_len the length of output digest value
 *
 * @return status of the operation
 */
Sec_Result SecKey_ComputeBaseKeyDigest(Sec_ProcessorHandle* processorHandle, SEC_BYTE* nonce, Sec_DigestAlgorithm alg,
        SEC_BYTE* digest, SEC_SIZE* digest_len);

/**
 * @brief Obtain a processor handle
 *
 * @param keyHandle key handle
 *
 * @return Processor handle
 */
Sec_ProcessorHandle* SecKey_GetProcessor(Sec_KeyHandle* keyHandle);

/**
 * @brief Generates a shared symmetric key and stores it in a specified location.
 *
 * A shared secret is calculated using the ECDH algorithm.  The shared
 * secret is converted to a key using the Concat KDF (SP800-56A Section
 * 5.8.1).  If the key with the same id already exists, the call will
 * overwrite the existing key with the new key.  SHA-256 is the digest
 * algorithm.
 *
 * @param keyHandle Handle of my private ECC key
 * @param otherPublicKey Public key for other party in key agreement
 * @param type_derived Type of key to generate. Only symmetric keys can be derived
 * @param id_derived 64-bit object id identifying the key to be generated
 * @param loc_id Location where the resulting key will be stored
 * @param digestAlgorithm Digest algorithm to use in KDF (typically SEC_DIGESTALGORITHM_SHA256)
 * @param otherInfo Input keying material
 *        AlgorithmID || PartyUInfo || PartyVInfo {|| SuppPubInfo }{|| SuppPrivInfo}
 * @param otherInfoSize	Size of otherInfo (in bytes)
 */
Sec_Result SecKey_ECDHKeyAgreementWithKDF(Sec_KeyHandle* keyHandle, Sec_ECCRawPublicKey* otherPublicKey,
        Sec_KeyType type_derived, SEC_OBJECTID id_derived, Sec_StorageLoc loc_derived, Sec_Kdf kdf,
        Sec_DigestAlgorithm digestAlgorithm, const SEC_BYTE* otherInfo, SEC_SIZE otherInfoSize);

/**
 * @brief Obtain a handle to a provisioned bundle
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the provisioned bundle that we are attempting to abtain
 * @param bundleHandle pointer to the output key handle
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_GetInstance(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id,
        Sec_BundleHandle** bundleHandle);

/**
 * @brief Provision a bundle
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the bundle to provision
 * @param location storage location where the bundle should be provisioned
 * @param data pointer to the input key container
 * @param data_len the size of the input key container
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_Provision(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id, Sec_StorageLoc location,
        SEC_BYTE* data, SEC_SIZE data_len);

/**
 * @brief Delete a provisioned bundle
 *
 * @param processorHandle secure processor handle
 * @param object_id id of the key to delete
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_Delete(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID object_id);

/**
 * @brief Release the bundle object
 *
 * @param bundleHandle bundle handle to release
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_Release(Sec_BundleHandle* bundleHandle);

/**
 * @brief Obtain the bundle data
 *
 * @param bundleHandle bundle handle
 * @param buffer pointer to the output buffer that will be filled with bundle data
 * @param buffer_len the length of the output buffer
 * @param written pointer to the output value specifying the number of bytes written to the
 * output buffer
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_Export(Sec_BundleHandle* bundleHandle, SEC_BYTE* buffer, SEC_SIZE buffer_len, SEC_SIZE* written);

/**
 * @brief Allocate platform specific memory optimized for encryption/decryption.  Used
 * With SEC_CIPHERMODE_ENCRYPT_NATIVEMEM and SEC_CIPHERMODE_DECRYPT_NATIVEMEM
 */
SEC_BYTE* Sec_NativeMalloc(Sec_ProcessorHandle* processorHandle, SEC_SIZE length);

/**
 * @brief Free memory allocated with Sec_NativeMalloc
 */
void Sec_NativeFree(Sec_ProcessorHandle* processorHandle, void* ptr);

Sec_Result SecCipher_ProcessCtrWithDataShift(Sec_CipherHandle* cipherHandle, SEC_BYTE* input, SEC_SIZE inputSize,
        SEC_BYTE* output, SEC_SIZE outputSize, SEC_SIZE* bytesWritten, SEC_SIZE dataShift);

Sec_Result SecKey_ExportKey(Sec_KeyHandle* keyHandle, SEC_BYTE* derivationInput, SEC_BYTE* exportedKey,
        SEC_SIZE keyBufferLen, SEC_SIZE* keyBytesWritten);

Sec_Result SecKey_GetProperties(Sec_KeyHandle* keyHandle, Sec_KeyProperties* keyProperties);

/**
 * @brief Checks secure boot configuration to verify that Secure Boot is enabled.
 */
Sec_Result SecCodeIntegrity_SecureBootEnabled(void);

Sec_Result SecSVP_SetTime(time_t time);

/* 2.2  */
Sec_Result Sec_OpaqueBufferMalloc(SEC_SIZE bufLength, void** handle, void* params)
        __attribute__((deprecated));

Sec_Result Sec_OpaqueBufferWrite(Sec_OpaqueBufferHandle* opaqueBufferHandle, SEC_SIZE offset, void* data,
        SEC_SIZE length) __attribute__((deprecated));

Sec_Result Sec_OpaqueBufferFree(Sec_OpaqueBufferHandle* opaqueBufferHandle, void* params) __attribute__((deprecated));

Sec_Result SecOpaqueBuffer_Malloc(SEC_SIZE bufLength, Sec_OpaqueBufferHandle** handle);

Sec_Result SecOpaqueBuffer_Write(Sec_OpaqueBufferHandle* opaqueBufferHandle, SEC_SIZE offset, SEC_BYTE* data,
        SEC_SIZE length);

Sec_Result SecOpaqueBuffer_Free(Sec_OpaqueBufferHandle* opaqueBufferHandle);

Sec_Result SecOpaqueBuffer_Release(Sec_OpaqueBufferHandle* opaqueBufferHandle, Sec_ProtectedMemHandle** svpHandle);

Sec_Result SecOpaqueBuffer_Copy(Sec_OpaqueBufferHandle* outOpaqueBufferHandle, SEC_SIZE out_offset,
        Sec_OpaqueBufferHandle* inOpaqueBufferHandle, SEC_SIZE in_offset, SEC_SIZE num_to_copy);

Sec_Result SecOpaqueBuffer_Check(Sec_DigestAlgorithm digestAlgorithm, Sec_OpaqueBufferHandle* opaqueBufferHandle,
        SEC_SIZE length, SEC_BYTE* expected, SEC_SIZE expectedLength);

Sec_Result SecKeyExchange_GetInstance(Sec_ProcessorHandle* processorHandle, Sec_KeyExchangeAlgorithm exchangeType,
        void* exchangeParameters, Sec_KeyExchangeHandle** keyExchangeHandle);

Sec_Result SecKeyExchange_GenerateKeys(Sec_KeyExchangeHandle* keyExchangeHandle, SEC_BYTE* publicKey,
        SEC_SIZE pubKeySize);

Sec_Result SecKeyExchange_ComputeSecret(Sec_KeyExchangeHandle* keyExchangeHandle, SEC_BYTE* otherPublicKey,
        SEC_SIZE otherPublicKeySize, Sec_KeyType typeComputed, SEC_OBJECTID idComputed, Sec_StorageLoc locComputed);

Sec_Result SecKeyExchange_Release(Sec_KeyExchangeHandle* keyExchangeHandle);

Sec_Result SecKey_Derive_BaseKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID idDerived, Sec_KeyType key_type,
        Sec_StorageLoc loc, SEC_BYTE* nonce);

Sec_Result SecKey_Derive_HKDF_BaseKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID idDerived,
        Sec_KeyType typeDerived, Sec_StorageLoc locDerived, Sec_MacAlgorithm macAlgorithm, SEC_BYTE* salt,
        SEC_SIZE saltSize, SEC_BYTE* info, SEC_SIZE infoSize, SEC_OBJECTID baseKeyId);

Sec_Result SecKey_Derive_ConcatKDF_BaseKey(Sec_ProcessorHandle* processorHandle, SEC_OBJECTID idDerived,
        Sec_KeyType typeDerived, Sec_StorageLoc locDerived, Sec_DigestAlgorithm digestAlgorithm, SEC_BYTE* otherInfo,
        SEC_SIZE otherInfoSize, SEC_OBJECTID baseKeyId);

typedef struct {
    SEC_SIZE clear;
    SEC_SIZE encrypted;
} SEC_MAP;

Sec_Result SecCipher_ProcessOpaqueWithMap(Sec_CipherHandle* cipherHandle, SEC_BYTE* iv, SEC_BYTE* input,
        SEC_SIZE inputSize, SEC_BOOL lastInput, SEC_MAP* map, SEC_SIZE mapLength,
        Sec_OpaqueBufferHandle** opaqueBufferHandle, SEC_SIZE* bytesWritten);

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_H_ */
