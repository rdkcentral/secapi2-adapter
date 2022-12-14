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

#include "keyctrl.h" // NOLINT
#include "jtype.h"
#include "sec_security_comcastids.h"
#include "sec_security_utils.h"
#include "sign.h"
#include "test_ctx.h"

#define BUFFER_SIZE 4096

// default params for jtype key container
struct default_jtype_data_struct {
    TestKey contentKey;
    TestKey encryptionKey;
    TestKc encKc;
    TestKey macKey;
    TestKc macKc;
    SEC_OBJECTID provisionId;
} __attribute__((aligned(32))) g_default_jtype_data = {
        .contentKey = TESTKEY_AES128,
        .encryptionKey = TESTKEY_AES128,
        .encKc = TESTKC_CONDITIONAL,
        .macKey = TESTKEY_HMAC160,
        .macKc = TESTKC_RAW,
        .provisionId = SEC_OBJECTID_USER_BASE};

static char opr_str[8][64] = {
        "Not-set",
        "SVP",
        "DTCP",
        "HDCP-1.4",
        "HDCP-2.2",
        "Analog",
        "Transcription-copy",
        "Unrestricted-copy"};

#define RIGHTS_INIT(x) memset(x, 0, SEC_KEYOUTPUTRIGHT_NUM)

std::string toB64(const SEC_BYTE* data, SEC_SIZE len);

/* Convenience function to provision the jtype key and session keys using the default
 * settings.  Since the jtype is a wrapped key, a check is performed to test if the
 * platform supports wrapped keys in the clear.  if it doesn't, SOC key container
 * needs to be used.
 */
static Sec_KeyHandle* provisionJTypeAndSession(TestCtx& ctx, std::string& jtypeKey) {
    Sec_KeyHandle* keyHandle = nullptr;

    do {
        if (SecKey_IsProvisioned(ctx.proc(), SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY) == SEC_TRUE &&
                SecKey_IsProvisioned(ctx.proc(), SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY) == SEC_TRUE) {
            SEC_PRINT("Session ENC and MAC keys are already provisioned.  Not provisioning again.\n");
        } else {
            SEC_PRINT("Provisioning session ENC and MAC.\n");

            //provision encryption key
            if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, SEC_STORAGELOC_RAM,
                        g_default_jtype_data.encryptionKey, g_default_jtype_data.encKc) == nullptr) {
                SEC_LOG_ERROR("ProvisionKey failed");
                break;
            }

            //provision maccing key
            if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, SEC_STORAGELOC_RAM,
                        g_default_jtype_data.macKey, g_default_jtype_data.macKc) == nullptr) {
                SEC_LOG_ERROR("ProvisionKey failed");
                break;
            }
        }

        //provision jtype key
        if (SecKey_Provision(ctx.proc(), g_default_jtype_data.provisionId, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
                    reinterpret_cast<SEC_BYTE*>(&jtypeKey[0]), jtypeKey.size()) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Provision failed");
            break;
        }

        if (SecKey_GetInstance(ctx.proc(), g_default_jtype_data.provisionId, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance failed for jtype key");
            break;
        }
    } while (false);

    return keyHandle;
}

/* SecCipher_GetInstance should fail with notBefore date in the future */
Sec_Result testKeyCtrlKeyNotYetAvail(int version, const char* alg) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    const char* notBeforeTimeStr = "2110-12-09T19:53:06Z";

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    do {
        /*  key avail in one hour */
        std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", g_default_jtype_data.contentKey,
                g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903",
                createDefaultRights(SEC_KEYTYPE_AES_128).c_str(), SEC_FALSE, 1, notBeforeTimeStr,
                "2030-12-09T19:53:06Z", g_default_jtype_data.macKey, version, alg);
        if (jtype.empty()) {
            SEC_LOG_ERROR("CreateJTypeContainer failed");
            break;
        }

        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        if (SecCipher_GetInstance(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, keyHandle,
                    iv, &cipherHandle) != SEC_RESULT_FAILURE) {
            SEC_LOG_ERROR("expected SecCipher_GetInstance to fail for jtype key with notBefore [%s]", notBeforeTimeStr);

            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (cipherHandle != nullptr)
        SecCipher_Release(cipherHandle);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

/* Generate a jtype key with usage of key only.  SecCipher_GetInstance should fail. */
Sec_Result testKeyCtrlKeyOnlyUsage(int version, const char* alg) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    do {
        /* expired key */
        std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", g_default_jtype_data.contentKey,
                g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903",
                createDefaultRights(SEC_KEYTYPE_AES_128).c_str(), SEC_FALSE, SEC_KEYUSAGE_KEY, "2010-12-09T19:53:06Z",
                "2025-12-09T01:02:03Z", g_default_jtype_data.macKey, version, alg);

        if (jtype.empty()) {
            SEC_LOG_ERROR("CreateJTypeContainer failed");
            break;
        }

        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        if (SecCipher_GetInstance(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, keyHandle,
                    iv, &cipherHandle) == SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR(
                    "expected Seccipher_GetInstance to fail for key with usage flag for 'key' only");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    if (cipherHandle != nullptr)
        SecCipher_Release(cipherHandle);

    return result;
}

/* Generate a jtype key with usage of data only. */
Sec_Result testKeyCtrlUnwrapWithKeyUsage(int version, const char* alg, TestKey contentKey) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey,
            g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903",
            createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(), SEC_FALSE, SEC_KEYUSAGE_KEY,
            "2010-12-09T19:53:06Z", "2025-12-09T01:02:03Z", g_default_jtype_data.macKey, version, alg);

    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    /* FIXME: actually encrypt the key bytes first */

    //create wrapped asn1 key
    std::vector<SEC_BYTE> wrapped = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> asn1;
    asn1.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE asn1_len;
    SEC_BYTE input[SEC_AES_BLOCK_SIZE];
    SEC_BYTE output[SEC_AES_BLOCK_SIZE];
    SEC_SIZE output_len;

    do {
        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        if (SecKey_GenerateWrappedKeyAsn1(wrapped.data(), wrapped.size(), SEC_KEYTYPE_AES_128,
                    g_default_jtype_data.provisionId, nullptr, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING,
                    asn1.data(), asn1.size(), &asn1_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GenerateWrappedKeyAsn1 failed");
            break;
        }
        asn1.resize(asn1_len);

        //provision wrapped
        SEC_PRINT("Provisioning wrapped\n");
        if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE + 1, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_ASN1,
                    asn1.data(), asn1.size()) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Provision failed");
            break;
        }

        SEC_PRINT("Wielding wrapped\n");
        if (SecCipher_SingleInputId(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT,
                    SEC_OBJECTID_USER_BASE + 1, nullptr, input, sizeof(input), output, sizeof(output),
                    &output_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_SingleInputId failed");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

Sec_Result testKeyCtrlUnwrapWithDataUsage(int version, const char* alg) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    //create wrapped asn1 key
    std::vector<SEC_BYTE> wrapped = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> asn1;
    asn1.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE asn1_len;
    SEC_BYTE input[SEC_AES_BLOCK_SIZE];
    SEC_BYTE output[SEC_AES_BLOCK_SIZE];
    SEC_SIZE output_len;
    std::string jtype;
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key(SEC_KEYCONTAINER_MAX_LEN, 0);
    SEC_SIZE exported_len = 0;

    do {
        if (ctx.init() != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("TestCtx.init failed");
            break;
        }

        jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", g_default_jtype_data.contentKey,
                g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903",
                createDefaultRights(SEC_KEYTYPE_AES_128).c_str(), SEC_TRUE, SEC_KEYUSAGE_DATA, "2010-12-09T19:53:06Z",
                "2025-12-09T01:02:03Z", g_default_jtype_data.macKey, version, alg);
        if (jtype.empty()) {
            SEC_LOG_ERROR("CreateJTypeContainer failed");
            return SEC_RESULT_FAILURE;
        }

        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        if (SecKey_GenerateWrappedKeyAsn1(wrapped.data(), wrapped.size(), SEC_KEYTYPE_AES_128, SEC_OBJECTID_USER_BASE,
                    nullptr, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, asn1.data(), asn1.size(), &asn1_len) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GenerateWrappedKeyAsn1 failed");
            break;
        }
        asn1.resize(asn1_len);

        //provision wrapped
        SEC_PRINT("Provisioning wrapped\n");
        if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE + 1, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_ASN1,
                    asn1.data(), asn1.size()) != SEC_RESULT_SUCCESS) {
            //this will fail on some platforms, others will fail when wielding cipher
            result = SEC_RESULT_SUCCESS;
            break;
        }

        SEC_PRINT("Wielding wrapped\n");
        if (SecCipher_SingleInputId(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT,
                    SEC_OBJECTID_USER_BASE + 1, nullptr, input, sizeof(input), output, sizeof(output),
                    &output_len) == SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Expected provisioning or wielding cipher to fail");
            break;
        }

        /* export the jtype and re-provision as exported to test exported logic as well */
        if (SecKey_ExportKey(keyHandle, derivation_input.data(), exported_key.data(), exported_key.size(),
                    &exported_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Export failed");
            break;
        }
        SecKey_Release(keyHandle);
        keyHandle = nullptr;
        SecKey_Delete(ctx.proc(), g_default_jtype_data.provisionId);

        /* provision exported */
        if (SecKey_Provision(ctx.proc(), g_default_jtype_data.provisionId, SEC_STORAGELOC_RAM,
                    SEC_KEYCONTAINER_EXPORTED, exported_key.data(), exported_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Provision failed for exported key");
            break;
        }

        if (SecCipher_SingleInputId(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT,
                    SEC_OBJECTID_USER_BASE + 1, nullptr, input, sizeof(input), output, sizeof(output),
                    &output_len) == SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Expected provisioning or wielding cipher to fail");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

/* SecCipher_Getinstance should fail with notOnOrAfter date < now */
Sec_Result testKeyCtrlKeyExpired(int version, const char* alg) {
    TestCtx ctx;

    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    const char* notOnOrAfter = "2015-12-09T19:53:06Z";
    Sec_Result result = SEC_RESULT_FAILURE;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", g_default_jtype_data.contentKey,
            g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903",
            createDefaultRights(SEC_KEYTYPE_AES_128).c_str(), SEC_FALSE, 1, "2010-12-09T19:53:06Z", notOnOrAfter,
            g_default_jtype_data.macKey, version, alg);

    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    do {
        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        if (SecCipher_GetInstance(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, keyHandle,
                    iv, &cipherHandle) == SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Expected Seccipher_GetInstance to fail for jtype key with expired notOnOrAfter [%s]",
                    notOnOrAfter);
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (cipherHandle != nullptr)
        SecCipher_Release(cipherHandle);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

/* On 32bit machine, provision should fail if key contains date > 2038/01/19 */
Sec_Result testKeyCtrlProvision32bit2038(int version, const char* alg) {
    TestCtx ctx;

    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    TestKey contentKey = TESTKEY_AES128;
    TestKey encryptionKey = TESTKEY_AES128;
    TestKc encKc = TestCreds::supports(CAPABILITY_CLEAR_JTYPE_WRAPPING) ? g_default_jtype_data.encKc : TESTKC_SOC;
    TestKey macKey = TESTKEY_HMAC160;
    TestKc macKc = TESTKC_RAW;
    const char* notOnOrAfter = "2038-12-09T19:53:06Z";

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey, encryptionKey,
            "9c621060-3a17-4813-8dcb-2e9187aaa903", createDefaultRights(SEC_KEYTYPE_AES_128).c_str(), SEC_FALSE, 1,
            "2010-12-09T19:53:06Z", notOnOrAfter, macKey, version, alg);
    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    //provision encryption key
    if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, SEC_STORAGELOC_RAM, encryptionKey, encKc) == nullptr) {
        SEC_LOG_ERROR("ProvisionKey failed");
        return SEC_RESULT_FAILURE;
    }
    //provision maccing key
    if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, SEC_STORAGELOC_RAM, macKey, macKc) == nullptr) {
        SEC_LOG_ERROR("ProvisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //provision jtype key
#if defined(__x86_64__) || defined(__ppc64__) || defined(__aarch64__)
    if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
                reinterpret_cast<SEC_BYTE*>(&jtype[0]), jtype.size()) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }
#else
    if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
                reinterpret_cast<SEC_BYTE*>(jtype.data()), jtype.size()) == SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("Expecting SecKey_Provision to fail on jtype with date '%s'", notOnOrAfter);
        return SEC_RESULT_FAILURE;
    }
#endif

    return SEC_RESULT_SUCCESS;
}

/* test that export fails with a jtype key where is_cacheable is false */
Sec_Result testKeyCtrlExportUnCachable(int version, const char* alg) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_KeyHandle* keyHandle = nullptr;
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key(SEC_KEYCONTAINER_MAX_LEN, 0);
    SEC_SIZE exported_len = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", g_default_jtype_data.contentKey,
            g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903",
            createDefaultRights(SEC_KEYTYPE_AES_128).c_str(), SEC_FALSE, 1, "2010-12-09T19:53:06Z",
            "2037-12-09T19:53:06Z", g_default_jtype_data.macKey, version, alg);

    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
        return SEC_RESULT_FAILURE;
    }

    do {
        //get properties from j-type
        Sec_KeyProperties jtype_props;
        if (SecKey_GetProperties(keyHandle, &jtype_props) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetProperties failed");
            break;
        }

        //export j-type key
        if (SecKey_ExportKey(keyHandle, derivation_input.data(), exported_key.data(), exported_key.size(),
                    &exported_len) == SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Expected SecKey_ExportKey to fail with cachable flag set to false");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

Sec_Result testKeyCtrlExpectedJTypeProperties(int version, const char* alg, TestKey contentKey) {
    TestCtx ctx;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    const char* notOnOrAfter = "2025-12-09T19:53:06Z";
    const char* notBefore = "2010-12-09T19:53:06Z";
    const char* keyId = "9c621060-3a17-4813-8dcb-2e9187aaa903";
    Sec_KeyProperties keyProps;
    SEC_BOOL cacheable = SEC_FALSE;
    Sec_KeyUsage keyUsage = SEC_KEYUSAGE_KEY;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey,
            g_default_jtype_data.encryptionKey, keyId, createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
            cacheable, keyUsage, notBefore, notOnOrAfter, g_default_jtype_data.macKey, version, alg);
    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
        return SEC_RESULT_FAILURE;
    }

    SecKey_GetProperties(keyHandle, &keyProps);
    SecKey_Release(keyHandle);

    if (strcmp(keyId, keyProps.keyId) != 0) {
        SEC_LOG_ERROR("Keyid mismatch  expecting '%s', received '%s'", keyId, keyProps.keyId);
        return SEC_RESULT_FAILURE;
    }
    if (strcmp(notOnOrAfter, keyProps.notOnOrAfter) != 0) {
        SEC_LOG_ERROR("NotOnOrAfter mismatch  expecting '%s', received '%s'", notOnOrAfter, keyProps.notOnOrAfter);
        return SEC_RESULT_FAILURE;
    }
    if (strcmp(notBefore, keyProps.notBefore) != 0) {
        SEC_LOG_ERROR("NotBefore mismatch  expecting '%s', received '%s'", notBefore, keyProps.notBefore);
        return SEC_RESULT_FAILURE;
    }
    if (TestCreds::getKeyType(contentKey) != keyProps.keyType) {
        SEC_LOG_ERROR("KeyType mismatch.  got %d, expected %d", keyProps.keyType, TestCreds::getKeyType(contentKey));
        return SEC_RESULT_FAILURE;
    }
    if (SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)) != keyProps.keyLength) {
        SEC_LOG_ERROR("KeyLength mismatch  expecting %d, received %d",
                SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)), keyProps.keyLength);
        return SEC_RESULT_FAILURE;
    }
    if (cacheable != keyProps.cacheable) {
        SEC_LOG_ERROR("Cacheable mismatch, expecting %d", cacheable);
        return SEC_RESULT_FAILURE;
    }
    if (keyUsage != keyProps.usage) {
        SEC_LOG_ERROR("Usage mismatch, expecting %d, received %d", keyUsage, keyProps.usage);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyCtrlBadB64Jtype(int version, const char* alg) {
    TestCtx ctx;
    TestKey contentKey = TESTKEY_AES128;
    TestKey encryptionKey = TESTKEY_AES128;
    TestKey macKey = TESTKEY_HMAC160;
    TestKc macKc = TESTKC_RAW;
    SEC_SIZE input_len = 256;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = "B" + createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey, encryptionKey,
                                      "9c621060-3a17-4813-8dcb-2e9187aaa903",
                                      createDefaultRights(SEC_KEYTYPE_AES_128).c_str(), SEC_FALSE, 1,
                                      "2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z", macKey, version, alg);
    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_IsProvisioned(ctx.proc(), SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY) == SEC_TRUE &&
            SecKey_IsProvisioned(ctx.proc(), SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY) == SEC_TRUE) {
        SEC_PRINT("Session ENC and MAC keys are already provisioned.  Not provisioning again.\n");
    } else {
        SEC_PRINT("Provisioning session ENC and MAC.\n");

        //provision encryption key
        if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, SEC_STORAGELOC_RAM,
                    g_default_jtype_data.encryptionKey, g_default_jtype_data.encKc) == nullptr) {
            SEC_LOG_ERROR("ProvisionKey failed");
            return SEC_RESULT_FAILURE;
        }

        //provision maccing key
        if (ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, SEC_STORAGELOC_RAM, g_default_jtype_data.macKey,
                    g_default_jtype_data.macKc) == nullptr) {
            SEC_LOG_ERROR("ProvisionKey failed");
            return SEC_RESULT_FAILURE;
        }
    }

    //provision jtype key
    if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
                reinterpret_cast<SEC_BYTE*>(&jtype[0]), jtype.size()) != SEC_RESULT_FAILURE) {
        SEC_LOG_ERROR("Expected provisionKey to failed with bad base64");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyCtrlExportEcc(TestKc kc) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    SEC_OBJECTID priv_id = SEC_OBJECTID_USER_BASE + 1;
    Sec_KeyHandle* keyHandle = nullptr;
    TestKey pub = TESTKEY_EC_PUB;
    TestKey priv = TESTKEY_EC_PRIV;
    std::vector<SEC_BYTE> clear = TestCtx::random(32);
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(16);
    SEC_BYTE exported_buffer[2000];
    std::vector<SEC_BYTE> signature;
    signature.resize(512);
    SEC_SIZE exported_size = 0;
    SEC_SIZE cipher_output_written = 0;
    SEC_SIZE signature_size = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if ((keyHandle = ctx.provisionKey(priv_id, SEC_STORAGELOC_RAM, priv, kc)) == nullptr) {
        SEC_LOG_ERROR("Provision priv key failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecSignature_SingleInputId(ctx.proc(), SEC_SIGNATUREALGORITHM_ECDSA_NISTP256, SEC_SIGNATUREMODE_SIGN, priv_id,
                clear.data(), clear.size(), signature.data(), &signature_size) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInputId failed on signing with priv ecc key");
        return SEC_RESULT_FAILURE;
    }
    signature.resize(signature_size);

    //verify
    if (verifyOpenSSL(SEC_SIGNATUREALGORITHM_ECDSA_NISTP256, pub, clear, signature) != SEC_TRUE) {
        SEC_LOG_ERROR("VerifyOpenSSL failed");
        return SEC_RESULT_FAILURE;
    }

    /* export priv key */
    if (SecKey_ExportKey(keyHandle, derivation_input.data(), exported_buffer, sizeof(exported_buffer),
                &exported_size) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Export failed for private ecc");
        return SEC_RESULT_FAILURE;
    }
    SecKey_Delete(ctx.proc(), priv_id);

    if (SecKey_Provision(ctx.proc(), priv_id, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, exported_buffer,
                exported_size) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    signature.resize(512);
    if (SecSignature_SingleInputId(ctx.proc(), SEC_SIGNATUREALGORITHM_ECDSA_NISTP256, SEC_SIGNATUREMODE_VERIFY, priv_id,
                clear.data(), clear.size(), signature.data(), &signature_size) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecSignature_SingleInputId failed on verification with priv ecc key");
        return SEC_RESULT_FAILURE;
    }
    signature.resize(signature_size);

    //verify
    if (verifyOpenSSL(SEC_SIGNATUREALGORITHM_ECDSA_NISTP256, pub, clear, signature) != SEC_TRUE) {
        SEC_LOG_ERROR("VerifyOpenSSL failed");
        return SEC_RESULT_FAILURE;
    }

    result = SEC_RESULT_SUCCESS;

    return result;
}

Sec_Result testKeyCtrlExportAes(TestKey aesKey, Sec_StorageLoc location) {
    Sec_Result result = SEC_RESULT_FAILURE;
    Sec_KeyHandle* keyHandle = nullptr;
    int i = 0;

    TestCtx ctx;
    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;
    SEC_BYTE exported_key[BUFFER_SIZE];
    SEC_SIZE exported_key_len = 0;
    SEC_SIZE exported_key_len2 = 0;
    Sec_CipherAlgorithm alg = SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING;
    Sec_KeyProperties keyProps;
    std::vector<SEC_BYTE> encrypted(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> decrypted(SEC_AES_BLOCK_SIZE);
    SEC_SIZE enc_len = 0;
    Sec_KeyContainer keyContainerType = SEC_KEYCONTAINER_RAW_AES_128;

    memset(&keyProps, 0, sizeof(Sec_KeyProperties));

    if (keyHandle != nullptr) {
        SecKey_Release(keyHandle);
    }
    keyHandle = nullptr;

    // input to export function
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_PRINT("SEC_KEYCONTAINER_RAW_AES_128\n");
    ProvKey* p = TestCreds::getKey(aesKey, TESTKC_RAW, id);
    SEC_PRINT("provisioning " SEC_OBJECTID_PATTERN "\n", id);

    if (SecKey_Provision(ctx.proc(), id, location,
                aesKey == TESTKEY_AES128 ? SEC_KEYCONTAINER_RAW_AES_128 : SEC_KEYCONTAINER_RAW_AES_256,
                &p->key[0], p->key.size()) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        delete p;
        return SEC_RESULT_FAILURE;
    }

    delete p;

    do {
        //encrypt
        if (SecCipher_SingleInputId(ctx.proc(), alg, SEC_CIPHERMODE_ENCRYPT, id, nullptr, clear.data(), clear.size(),
                    encrypted.data(), encrypted.size(), &enc_len) != SEC_RESULT_SUCCESS) {

            SEC_LOG_ERROR("Encrypt failed");
            break;
        }

        if (SecKey_GetInstance(ctx.proc(), id, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance failed");
            break;
        }
        // get size
        if (SecKey_ExportKey(keyHandle, derivation_input.data(), nullptr, 0,
                    &exported_key_len2) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_ExportKey failed for key size");
            break;
        }
        if (SecKey_ExportKey(keyHandle, derivation_input.data(), exported_key, sizeof(exported_key),
                    &exported_key_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_ExportKey failed");
            break;
        }
        SecKey_Release(keyHandle);
        keyHandle = nullptr;

        if (exported_key_len2 != exported_key_len) {
            SEC_LOG_ERROR("Exported key length mismatch, expected %d, received %d",
                    exported_key_len2, exported_key_len);
            break;
        }

        // NOTE: on intel, exported keys MUST be provisioned with the same object_id as when
        //       they were originally provisioned.
        SEC_PRINT("provisioning exported " SEC_OBJECTID_PATTERN "\n", id);
        if (SecKey_Provision(ctx.proc(), id, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, exported_key,
                    exported_key_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Provision failed");
            return SEC_RESULT_FAILURE;
        }

        // test decrypt with exported key
        if (SecCipher_SingleInputId(ctx.proc(), alg, SEC_CIPHERMODE_DECRYPT, id, nullptr, encrypted.data(),
                    encrypted.size(), decrypted.data(), decrypted.size(), &enc_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Decrypt failed");
            break;
        }
        TestCtx::printHex("derivation input", derivation_input);
        TestCtx::printHex("       encrypted", encrypted);
        TestCtx::printHex("       decrypted", decrypted);
        TestCtx::printHex("           clear", clear);
        if (clear != decrypted) {
            SEC_LOG_ERROR("Decrypted vector mismatch");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

Sec_Result testKeyCtrlExportDerived() {
    Sec_Result result = SEC_RESULT_FAILURE;
    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;
    SEC_BYTE exported_key[BUFFER_SIZE];
    SEC_SIZE exported_key_len = 0;
    Sec_KeyHandle* keyHandle = nullptr;
    TestCtx ctx;
    SEC_BYTE enc_output[256];
    SEC_SIZE enc_output_len = 0;
    SEC_BYTE enc_output2[256];
    SEC_SIZE enc_output_len2 = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    std::vector<SEC_BYTE> input = TestCtx::random(25);
    TestCtx::printHex("input", input);

    if (SecKey_Derive_VendorAes128(ctx.proc(), id, SEC_STORAGELOC_RAM, input.data(),
                input.size()) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Derive_VendorAes128 failed");
        return SEC_RESULT_FAILURE;
    }

    do {
        if (SecKey_GetInstance(ctx.proc(), id, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance failed");
            break;
        }

        if (SecCipher_SingleInputId(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, id,
                    nullptr, derivation_input.data(), derivation_input.size(), enc_output, sizeof(enc_output),
                    &enc_output_len) != SEC_RESULT_SUCCESS) {

            SEC_LOG_ERROR("Encrypt failed");
            break;
        }

        if (SecKey_ExportKey(keyHandle, derivation_input.data(), exported_key, sizeof(exported_key),
                    &exported_key_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_ExportKey failed for derived key type");
            break;
        }
        SecKey_Release(keyHandle);
        keyHandle = nullptr;
        SecKey_Delete(ctx.proc(), id);

        /* import exported derived key */
        if (SecKey_Provision(ctx.proc(), id, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, exported_key,
                    exported_key_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Provision failed for exported key");
            return SEC_RESULT_FAILURE;
        }
        if (SecKey_GetInstance(ctx.proc(), id, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance failed");
            break;
        }
        if (SecCipher_SingleInputId(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, id,
                    nullptr, enc_output, enc_output_len, enc_output2, sizeof(enc_output2), &enc_output_len2) !=
                SEC_RESULT_SUCCESS) {

            SEC_LOG_ERROR("Decrypt failed");
            break;
        }
        if (derivation_input.size() != enc_output_len2) {
            SEC_LOG_ERROR("Enc output size mismatch, expected %d, %d", derivation_input.size(), enc_output_len2);
            break;
        }
        Sec_PrintHex(derivation_input.data(), derivation_input.size());
        SEC_PRINT("\n");
        Sec_PrintHex(enc_output2, enc_output_len2);
        SEC_PRINT("\n");
        if (memcmp(derivation_input.data(), enc_output2, enc_output_len2) != 0) {
            SEC_LOG_ERROR("Enc output mismatch");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

Sec_Result testKeyCtrlExpectedExportedProperties(int version, const char* alg, TestKey contentKey) {
    TestCtx ctx;

    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    const char* notOnOrAfter = "2025-12-09T19:53:06Z";
    const char* notBefore = "2010-12-09T19:53:06Z";
    const char* keyId = "9c621060-3a17-4813-8dcb-2e9187aaa903";
    Sec_KeyProperties keyProps;
    SEC_BOOL cacheable = SEC_TRUE;
    Sec_KeyUsage keyUsage = SEC_KEYUSAGE_KEY;
    SEC_BYTE exported_key[BUFFER_SIZE];
    SEC_SIZE exported_key_len = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[1] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    jtypeRights[2] = SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey,
            g_default_jtype_data.encryptionKey, keyId, b64rights.c_str(), cacheable, keyUsage, notBefore, notOnOrAfter,
            g_default_jtype_data.macKey, version, alg);

    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (SecKey_ExportKey(keyHandle, &derivation_input[0], exported_key, sizeof(exported_key), &exported_key_len) !=
            SEC_RESULT_SUCCESS) {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }

    SecKey_Release(keyHandle);
    keyHandle = nullptr;
    SecKey_Delete(ctx.proc(), SEC_OBJECTID_USER_BASE);

    // reprovision exported
    if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
                exported_key, exported_key_len) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed for exported key");
        return SEC_RESULT_FAILURE;
    }
    if (SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed for exported key");
        return SEC_RESULT_FAILURE;
    }

    SecKey_GetProperties(keyHandle, &keyProps);
    SecKey_Release(keyHandle);
    keyHandle = nullptr;

    if (strcmp(keyId, keyProps.keyId) != 0) {
        SEC_LOG_ERROR("Keyid mismatch  expecting '%s', received '%s'", keyId, keyProps.keyId);
        return SEC_RESULT_FAILURE;
    }
    if (strcmp(notOnOrAfter, keyProps.notOnOrAfter) != 0) {
        SEC_LOG_ERROR("NotOnOrAfter mismatch  expecting '%s', received '%s'", notOnOrAfter, keyProps.notOnOrAfter);
        return SEC_RESULT_FAILURE;
    }
    if (strcmp(notBefore, keyProps.notBefore) != 0) {
        SEC_LOG_ERROR("NotBefore mismatch  expecting '%s', received '%s'", notBefore, keyProps.notBefore);
        return SEC_RESULT_FAILURE;
    }
    if (TestCreds::getKeyType(contentKey) != keyProps.keyType) {
        SEC_LOG_ERROR("KeyType mismatch.  got %d, expected %d", keyProps.keyType, TestCreds::getKeyType(contentKey));
        return SEC_RESULT_FAILURE;
    }
    if (SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)) != keyProps.keyLength) {
        SEC_LOG_ERROR("KeyLength mismatch  expecting %d, received %d",
                SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)), keyProps.keyLength);
        return SEC_RESULT_FAILURE;
    }
    if (cacheable != keyProps.cacheable) {
        SEC_LOG_ERROR("Cacheable mismatch, expecting %d", cacheable);
        return SEC_RESULT_FAILURE;
    }
    if (keyUsage != keyProps.usage) {
        SEC_LOG_ERROR("Usage mismatch, expecting %d, received %d", keyUsage, keyProps.usage);
        return SEC_RESULT_FAILURE;
    }

    if (memcmp(keyProps.rights, jtypeRights, 8) != 0) {
        SEC_LOG_ERROR("Keyrights mismatch");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

/* export a key, re-provision it, then export it again
 */
Sec_Result testKeyCtrlExportProvisionExport(int version, const char* alg, TestKey contentKey) {
    TestCtx ctx;

    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    const char* notOnOrAfter = "2025-12-09T19:53:06Z";
    const char* notBefore = "2010-12-09T19:53:06Z";
    const char* keyId = "9c621060-3a17-4813-8dcb-2e9187aaa903";
    Sec_KeyProperties keyProps;
    SEC_BOOL cacheable = SEC_TRUE;
    Sec_KeyUsage keyUsage = SEC_KEYUSAGE_KEY;
    SEC_BYTE exported_key[BUFFER_SIZE];
    SEC_SIZE exported_key_len = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[1] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    jtypeRights[2] = SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey,
            g_default_jtype_data.encryptionKey, keyId, b64rights.c_str(), cacheable, keyUsage, notBefore, notOnOrAfter,
            g_default_jtype_data.macKey, version, alg);

    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (SecKey_ExportKey(keyHandle, &derivation_input[0], exported_key, sizeof(exported_key), &exported_key_len) !=
            SEC_RESULT_SUCCESS) {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }

    SecKey_Release(keyHandle);
    keyHandle = nullptr;
    SecKey_Delete(ctx.proc(), SEC_OBJECTID_USER_BASE);

    // reprovision exported
    if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
                exported_key, exported_key_len) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed for exported key");
        return SEC_RESULT_FAILURE;
    }
    if (SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed for exported key");
        return SEC_RESULT_FAILURE;
    }

    // export it again
    derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    if (SecKey_ExportKey(keyHandle, &derivation_input[0], exported_key, sizeof(exported_key), &exported_key_len) !=
            SEC_RESULT_SUCCESS) {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }
    SecKey_Release(keyHandle);
    keyHandle = nullptr;
    SecKey_Delete(ctx.proc(), SEC_OBJECTID_USER_BASE);

    // reprovision exported
    if (SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
                exported_key, exported_key_len) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed for exported key");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &keyHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_GetInstance failed for exported key");
        return SEC_RESULT_FAILURE;
    }

    SecKey_GetProperties(keyHandle, &keyProps);
    SecKey_Release(keyHandle);
    keyHandle = nullptr;

    if (strcmp(keyId, keyProps.keyId) != 0) {
        SEC_LOG_ERROR("Keyid mismatch  expecting '%s', received '%s'", keyId, keyProps.keyId);
        return SEC_RESULT_FAILURE;
    }
    if (strcmp(notOnOrAfter, keyProps.notOnOrAfter) != 0) {
        SEC_LOG_ERROR("NotOnOrAfter mismatch  expecting '%s', received '%s'", notOnOrAfter, keyProps.notOnOrAfter);
        return SEC_RESULT_FAILURE;
    }
    if (strcmp(notBefore, keyProps.notBefore) != 0) {
        SEC_LOG_ERROR("NotBefore mismatch  expecting '%s', received '%s'", notBefore, keyProps.notBefore);
        return SEC_RESULT_FAILURE;
    }
    if (TestCreds::getKeyType(contentKey) != keyProps.keyType) {
        SEC_LOG_ERROR("KeyType mismatch.  got %d, expected %d", keyProps.keyType, TestCreds::getKeyType(contentKey));
        return SEC_RESULT_FAILURE;
    }
    if (SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)) != keyProps.keyLength) {
        SEC_LOG_ERROR("KeyLength mismatch  expecting %d, received %d",
                SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)), keyProps.keyLength);
        return SEC_RESULT_FAILURE;
    }
    if (cacheable != keyProps.cacheable) {
        SEC_LOG_ERROR("Cacheable mismatch, expecting %d", cacheable);
        return SEC_RESULT_FAILURE;
    }
    if (keyUsage != keyProps.usage) {
        SEC_LOG_ERROR("Usage mismatch, expecting %d, received %d", keyUsage, keyProps.usage);
        return SEC_RESULT_FAILURE;
    }

    if (memcmp(keyProps.rights, jtypeRights, 8) != 0) {
        SEC_LOG_ERROR("Keyrights mismatch");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

// get just size needed for key by passing NULL out buffer to KeyExport call
Sec_Result testKeyCtrlKeyExportGetSize(int version, const char* alg) {
    TestCtx ctx;

    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    const char* notOnOrAfter = "2025-12-09T19:53:06Z";
    const char* notBefore = "2010-12-09T19:53:06Z";
    const char* keyId = "9c621060-3a17-4813-8dcb-2e9187aaa903";
    Sec_KeyProperties keyProps;
    SEC_BOOL cacheable = SEC_TRUE;
    Sec_KeyUsage keyUsage = SEC_KEYUSAGE_KEY;
    SEC_BYTE exported_key[BUFFER_SIZE];
    SEC_SIZE exported_key_len = 0;
    SEC_SIZE exported_key_len2 = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[1] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    jtypeRights[2] = SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", g_default_jtype_data.contentKey,
            g_default_jtype_data.encryptionKey, keyId, b64rights.c_str(), cacheable,
            keyUsage, notBefore, notOnOrAfter, g_default_jtype_data.macKey, version,
            alg);

    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    // get size
    if (SecKey_ExportKey(keyHandle, &derivation_input[0], nullptr, 0, &exported_key_len2) != SEC_RESULT_SUCCESS) {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed while getting key length");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_ExportKey(keyHandle, &derivation_input[0], exported_key, sizeof(exported_key), &exported_key_len) !=
            SEC_RESULT_SUCCESS) {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }
    SecKey_Release(keyHandle);
    keyHandle = nullptr;

    if (exported_key_len != exported_key_len2) {
        SEC_LOG_ERROR("Exported key length mismatch, expected %d, received %d", exported_key_len2, exported_key_len);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyCtrlKeyExportHmac(TestKey macKey, Sec_StorageLoc location) {
    TestCtx ctx;
    Sec_Result result = SEC_RESULT_FAILURE;

    Sec_KeyHandle* keyHandle = nullptr;
    TestKc macKc = TESTKC_RAW;
    Sec_KeyProperties keyProps;
    SEC_BYTE exported_key[BUFFER_SIZE];
    SEC_SIZE exported_key_len = 0;
    SEC_SIZE exported_key_len2 = 0;
    Sec_MacHandle* macHandle = nullptr;
    SEC_BYTE mac_output[256];
    SEC_SIZE mac_output_len = 0;
    SEC_BYTE mac_output2[256];
    SEC_SIZE mac_output_len2 = 0;
    SEC_OBJECTID id = SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY;

    memset(mac_output, 0, sizeof(mac_output));
    memset(mac_output2, 0, sizeof(mac_output2));

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    do {
        if (ctx.init() != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("TestCtx.init failed");
            break;
        }

        //provision maccing key
        if (ctx.provisionKey(id, location, macKey, macKc) == nullptr) {
            SEC_LOG_ERROR("ProvisionKey failed");
            break;
        }

        if (SecKey_GetInstance(ctx.proc(), id, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance failed for session mac key");
            break;
        }

        if (SecMac_GetInstance(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA1, keyHandle, &macHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecMac_GetInstance failed for hmac key");
            break;
        }
        if (SecMac_Update(macHandle, &derivation_input[0], derivation_input.size()) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecMac_GetInstance failed for hmac key");
            break;
        }

        SecMac_Release(macHandle, mac_output, &mac_output_len);
        macHandle = nullptr;

        // get size
        if (SecKey_ExportKey(keyHandle, &derivation_input[0], nullptr, 0, &exported_key_len2) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_ExportKey failed while getting key length");
            break;
        }

        if (SecKey_ExportKey(keyHandle, &derivation_input[0], exported_key, sizeof(exported_key), &exported_key_len) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_ExportKey failedi for mac key");
            break;
        }
        SecKey_Release(keyHandle);
        keyHandle = nullptr;

        SecKey_Delete(ctx.proc(), id);

        if (exported_key_len != exported_key_len2) {
            SEC_LOG_ERROR("Exported key length mismatch, expected %d, received %d",
                    exported_key_len2, exported_key_len);
            break;
        }

        if (SecKey_Provision(ctx.proc(), id, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, exported_key,
                    exported_key_len) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_Provision failed for exported hmac key");
            return SEC_RESULT_FAILURE;
        }
        if (SecKey_GetInstance(ctx.proc(), id, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance failed for session mac key");
            break;
        }
        if (SecMac_GetInstance(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA1, keyHandle, &macHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecMac_GetInstance failed for hmac key");
            break;
        }
        if (SecMac_Update(macHandle, &derivation_input[0], derivation_input.size()) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecMac_Update failed for hmac key");
            break;
        }

        SecMac_Release(macHandle, mac_output2, &mac_output_len2);
        macHandle = nullptr;

        if (mac_output_len != mac_output_len2) {
            SEC_LOG_ERROR("Mac output size mismatch, %d, %d", mac_output_len, mac_output_len2);
            break;
        }
        Sec_PrintHex(mac_output, mac_output_len);
        SEC_PRINT("\n");
        Sec_PrintHex(mac_output2, mac_output_len2);
        SEC_PRINT("\n");
        if (memcmp(mac_output, mac_output2, mac_output_len2) != 0) {
            SEC_LOG_ERROR("Mac output mismatch");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (macHandle != nullptr)
        SecMac_Release(macHandle, mac_output, &mac_output_len);
    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

/* Only Opaque buffers can be used when SVP is required */
Sec_Result testKeyCtrlCipherFailsSvpNonOpaque(int version, const char* alg, Sec_CipherAlgorithm cipher_algorithm) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    SEC_BYTE clear_text[SEC_AES_BLOCK_SIZE] = {0x01};
    SEC_BYTE cipher_text[SEC_AES_BLOCK_SIZE];
    SEC_SIZE bytesWritten = 0;
    const char* notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char* notOnOrAfterTimeStr = "2110-12-09T19:53:06Z";
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0] = SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    do {
        /*  key avail in one hour */
        std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", g_default_jtype_data.contentKey,
                g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903", b64rights.c_str(), SEC_TRUE,
                1, notBeforeTimeStr, notOnOrAfterTimeStr, g_default_jtype_data.macKey, version, alg);
        if (jtype.empty()) {
            SEC_LOG_ERROR("CreateJTypeContainer failed");
            break;
        }

        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        if (SecCipher_GetInstance(ctx.proc(), cipher_algorithm, SEC_CIPHERMODE_ENCRYPT, keyHandle, iv, &cipherHandle) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_GetInstance failed");
            break;
        }

        if (SecCipher_Process(cipherHandle, clear_text, sizeof(clear_text), SEC_TRUE, cipher_text, sizeof(cipher_text),
                    &bytesWritten) == SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("expected SecCipher_Process to fail when processing non-opaque buffer with SVP required");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (cipherHandle != nullptr)
        SecCipher_Release(cipherHandle);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

/* cipher process succeeds with svp required and opaque buffer */
Sec_Result testKeyCtrlCipherSvpOpaque(int version, const char* alg, TestKey contentKey,
        Sec_CipherAlgorithm cipher_algorithm) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    Sec_OpaqueBufferHandle* clearOpaqueBufferHandle = nullptr;
    Sec_OpaqueBufferHandle* cipherOpaqueBufferHandle = nullptr;
    SEC_SIZE bytesWritten = 0;
    const char* notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char* notOnOrAfterTimeStr = "2110-12-09T19:53:06Z";
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    SEC_BYTE clear_data[SEC_AES_BLOCK_SIZE] = {0x01};

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0] = SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    do {
        std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey,
                g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903", b64rights.c_str(), SEC_TRUE,
                1, notBeforeTimeStr, notOnOrAfterTimeStr, g_default_jtype_data.macKey, version, alg);

        if (jtype.empty()) {
            SEC_LOG_ERROR("CreateJTypeContainer failed");
            break;
        }

        if (ctx.init() != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("TestCtx.init failed");
            return SEC_RESULT_FAILURE;
        }

        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        /* init opaque buffers */
        if (SecOpaqueBuffer_Malloc(SEC_AES_BLOCK_SIZE, &clearOpaqueBufferHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
            break;
        }
        if (SecOpaqueBuffer_Malloc(SEC_AES_BLOCK_SIZE, &cipherOpaqueBufferHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
            break;
        }
        if (SecOpaqueBuffer_Write(clearOpaqueBufferHandle, 0, clear_data, SEC_AES_BLOCK_SIZE) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecOpaqueBuffer_Write failed");
            break;
        }

        if (SecCipher_GetInstance(ctx.proc(), cipher_algorithm, SEC_CIPHERMODE_ENCRYPT, keyHandle, iv, &cipherHandle) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_GetInstance failed");
            break;
        }

        if (SecCipher_ProcessOpaque(cipherHandle, clearOpaqueBufferHandle, cipherOpaqueBufferHandle, SEC_AES_BLOCK_SIZE,
                    SEC_TRUE, &bytesWritten) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_ProcessOpaque failed");
            break;
        }
        if (bytesWritten != SEC_AES_BLOCK_SIZE) {
            SEC_LOG_ERROR("Expected output size to be 16, received %d", (int) bytesWritten);
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (cipherHandle != nullptr)
        SecCipher_Release(cipherHandle);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    if (clearOpaqueBufferHandle != nullptr)
        SecOpaqueBuffer_Free(clearOpaqueBufferHandle);

    if (cipherOpaqueBufferHandle != nullptr)
        SecOpaqueBuffer_Free(cipherOpaqueBufferHandle);

    return result;
}

Sec_Result testKeyCtrlCipherSvpDataShiftOpaque(int version, const char* alg) {
    // Data Shift not supported
#if 0
    Sec_Result result = SEC_RESULT_FAILURE;
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    const char *notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char *notOnOrAfterTimeStr = "2110-12-09T19:53:06Z";
    TestCtx ctx;
    Sec_OpaqueBufferHandle *inputHandle1 = nullptr;
    Sec_OpaqueBufferHandle *inputHandle2 = nullptr;
    Sec_OpaqueBufferHandle *outputHandle = nullptr;
    SEC_SIZE written = 0;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle *handle = nullptr;
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

do {
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER",
        "HS256",
        g_default_jtype_data.contentKey,
        g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        b64rights.c_str(), SEC_TRUE, 1,
        notBeforeTimeStr,
        notOnOrAfterTimeStr,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.empty()) {
        SEC_LOG_ERROR("CreateJTypeContainer failed");
        break;
    }

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (nullptr == (handle = _provisionJTypeAndSession(ctx, jtype)))
    {
        break;
    }

    if (!= SEC_RESULT_SUCCESS) SecCipher_GetInstance(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, handle,
        &iv[0], &cipherHandle)) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        break;
    }

    if (SecOpaqueBuffer_Malloc(8, &inputHandle1) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        break;
    }

    if (SecOpaqueBuffer_Malloc(256-8, &inputHandle2) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        break;
    }

    if (SecOpaqueBuffer_Malloc(256, &outputHandle) != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        break;
    }

    if (!= SEC_RESULT_SUCCESS) SecCipher_ProcessOpaque(cipherHandle,
        inputHandle1, outputHandle, 8, SEC_FALSE,
        &written)) {
        SEC_LOG_ERROR("SecCipher_ProcessOpaque failed");
        break;
    }

    if (SecCipher_ProcessCtrWithOpaqueDataShift(cipherHandle, inputHandle2, outputHandle, 256-8, &written, 8) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecCipher_ProcessCtrWithOpaqueDataShift failed");
        break;
    }

    result = SEC_RESULT_SUCCESS;

        } while(false);


    if (cipherHandle)
        SecCipher_Release(cipherHandle);
    if (handle)
        SecKey_Release(handle);
    if (outputHandle)
        SecOpaqueBuffer_Free(outputHandle);
    if (inputHandle1)
        SecOpaqueBuffer_Free(inputHandle1);
    if (inputHandle2)
        SecOpaqueBuffer_Free(inputHandle2);

    return result;
#endif
    SEC_LOG_ERROR("SecCipher_ProcessCtrWithOpaqueDataShift not supported");
    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyCtrlSvpCheckOpaque(int version, const char* alg, TestKey contentKey) {
    TestCtx ctx;
    Sec_Result result = SEC_RESULT_FAILURE;
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    const char* notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char* notOnOrAfterTimeStr = "2110-12-09T19:53:06Z";
    SEC_SIZE written = 0;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    Sec_KeyHandle* keyHandle2 = nullptr;
    std::vector<SEC_BYTE> expected = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> input(SEC_AES_BLOCK_SIZE, 0);
    SEC_SIZE bytesWritten = 0;
    Sec_OpaqueBufferHandle* opaqueBufferHandle = nullptr;

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0] = SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    do {
        std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", contentKey,
                g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903", b64rights.c_str(), SEC_TRUE,
                1, notBeforeTimeStr, notOnOrAfterTimeStr, g_default_jtype_data.macKey, version, alg);

        if (jtype.empty()) {
            SEC_LOG_ERROR("CreateJTypeContainer failed");
            break;
        }
        if (ctx.init() != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("TestCtx.init failed");
            return SEC_RESULT_FAILURE;
        }
        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        /* provision key setup expected test data */
        keyHandle2 = ctx.provisionKey(SEC_OBJECTID_USER_BASE + 1, SEC_STORAGELOC_RAM, contentKey, TESTKC_RAW,
                SEC_FALSE);
        if (keyHandle2 == nullptr) {
            SEC_LOG_ERROR("ctx.provisionKey failed");
            break;
        }

        if (SecCipher_SingleInput(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT,
                    keyHandle2, nullptr, &expected[0], expected.size(), &input[0], input.size(), &bytesWritten) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_SingleInputId failed");
            break;
        }

        /* cipher handle using jtype key */
        if (SecCipher_GetInstance(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, keyHandle,
                    nullptr, &cipherHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_GetInstance failed");
            return SEC_RESULT_FAILURE;
        }

        TestCtx::printHex("   input", input);
        TestCtx::printHex("expected", expected);

        if (SecOpaqueBuffer_Malloc(input.size(), &opaqueBufferHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
            return SEC_RESULT_FAILURE;
        }

        if (SecOpaqueBuffer_Write(opaqueBufferHandle, 0, &input[0], input.size()) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecOpaqueBuffer_Write failed");
            return SEC_RESULT_FAILURE;
        }

        if (SecCipher_KeyCheckOpaque(cipherHandle, opaqueBufferHandle, SEC_AES_BLOCK_SIZE, &expected[0]) !=
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_KeyCheckOpaque failed");
            return SEC_RESULT_FAILURE;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (cipherHandle != nullptr)
        SecCipher_Release(cipherHandle);
    if (opaqueBufferHandle != nullptr)
        SecOpaqueBuffer_Free(opaqueBufferHandle);
    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

/* Only Opaque buffers can be used when SVP is required */
Sec_Result testKeyCtrlProcessCtrDataShiftFailsSvpNonOpaque(int version, const char* alg) {
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle* cipherHandle = nullptr;
    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE] = {0x01};
    SEC_BYTE clear_text[SEC_AES_BLOCK_SIZE] = {0x01};
    SEC_BYTE cipher_text[SEC_AES_BLOCK_SIZE];
    SEC_SIZE bytesWritten = 0;
    const char* notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char* notOnOrAfterTimeStr = "2110-12-09T19:53:06Z";
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0] = SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    do {
        /*  key avail in one hour */
        std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256", g_default_jtype_data.contentKey,
                g_default_jtype_data.encryptionKey, "9c621060-3a17-4813-8dcb-2e9187aaa903", b64rights.c_str(), SEC_TRUE,
                1, notBeforeTimeStr, notOnOrAfterTimeStr, g_default_jtype_data.macKey, version, alg);
        if (jtype.empty()) {
            SEC_LOG_ERROR("CreateJTypeContainer failed");
            break;
        }

        if ((keyHandle = provisionJTypeAndSession(ctx, jtype)) == nullptr) {
            break;
        }

        if (SecCipher_GetInstance(ctx.proc(), SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, keyHandle, iv,
                    &cipherHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecCipher_GetInstance failed");
            break;
        }

        if (SecCipher_ProcessCtrWithDataShift(cipherHandle, clear_text, sizeof(clear_text), cipher_text,
                    sizeof(cipher_text), &bytesWritten, 8) == SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Expected SecCipher_ProcessCtrWithDataShift to fail when processing non-opaque buffer with"
                          " SVP required");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (cipherHandle != nullptr)
        SecCipher_Release(cipherHandle);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}

Sec_Result testKeyCtrlKeyExportSmallBuffer() {
    Sec_Result result = SEC_RESULT_FAILURE;

    Sec_KeyHandle* keyHandle = nullptr;
    SEC_BYTE exported_key[8];
    SEC_SIZE exported_key_len = 0;
    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE + 50;
    Sec_ProcessorHandle* processorHandle = nullptr;
    Sec_StorageLoc location = SEC_STORAGELOC_RAM;
    TestCtx ctx;

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> aesKey = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_Provision(ctx.proc(), id, location, SEC_KEYCONTAINER_RAW_AES_128, &aesKey[0], aesKey.size()) !=
            SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    do {
        if (SecKey_GetInstance(ctx.proc(), id, &keyHandle) != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("SecKey_GetInstance failed");
            break;
        }

        if (SecKey_ExportKey(keyHandle, &derivation_input[0], exported_key, sizeof(exported_key), &exported_key_len) ==
                SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("Expected SecKey_ExportKey to fail with under-sized output buffer");
            break;
        }

        result = SEC_RESULT_SUCCESS;
    } while (false);

    if (keyHandle != nullptr)
        SecKey_Release(keyHandle);

    return result;
}
