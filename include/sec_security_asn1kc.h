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

#ifndef SEC_COMMON_17

#ifndef SEC_SECURITY_ASN1KC_H_
#define SEC_SECURITY_ASN1KC_H_

#include "sec_security_datatype.h"
#include <openssl/asn1t.h>
#include <openssl/safestack.h>
#include <openssl/stack.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque certificate handle
 *
 */
#define ASN1KCATTRIBUTE_T_CHOICE_INTEGER 0
#define ASN1KCATTRIBUTE_T_CHOICE_BITSTRING 1
#define ASN1KCATTRIBUTE_T_CHOICE_OCTETSTRING 2
#define ASN1KCATTRIBUTE_T_CHOICE_NULL 3
#define ASN1KCATTRIBUTE_T_CHOICE_IA5STRING 4
#define ASN1KCATTRIBUTE_T_CHOICE_UTCTIME 5

typedef struct {
    int type;
    union {
        ASN1_INTEGER* integer;
        ASN1_BIT_STRING* bitstring;
        ASN1_OCTET_STRING* octetstring;
        ASN1_NULL* null;
        ASN1_IA5STRING* ia5string;
        ASN1_UTCTIME* utctime;
    } c;
} Asn1KCAttribute_t_c;

typedef struct {
    ASN1_IA5STRING* name;
    Asn1KCAttribute_t_c* value;
} Asn1KCAttribute_t;

typedef STACK_OF(Asn1KCAttribute_t) Sec_Asn1KC;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
DECLARE_STACK_OF(Asn1KCAttribute_t);
#define sk_Asn1KCAttribute_t_push(st, val) SKM_sk_push(Asn1KCAttribute_t, st, val)
#define sk_Asn1KCAttribute_t_value(st, i) SKM_sk_value(Asn1KCAttribute_t, st, i)
#define sk_Asn1KCAttribute_t_num(st) SKM_sk_num(Asn1KCAttribute_t, st)
#else
DEFINE_STACK_OF(Asn1KCAttribute_t); // NOLINT
#endif

Sec_Asn1KC* SecAsn1KC_Alloc();

void SecAsn1KC_Free(Sec_Asn1KC* kc);

Sec_Result SecAsn1KC_Encode(Sec_Asn1KC* kc, SEC_BYTE* buf, SEC_SIZE buf_len, SEC_SIZE* written);

Sec_Asn1KC* SecAsn1KC_Decode(const SEC_BYTE* buf, SEC_SIZE buf_len);

SEC_BOOL SecAsn1KC_HasAttr(Sec_Asn1KC* kc, const char* key);

Sec_Result SecAsn1KC_AddAttrUlong(Sec_Asn1KC* kc, const char* key, uint64_t val);

Sec_Result SecAsn1KC_AddAttrUint64(Sec_Asn1KC* kc, const char* key, uint64_t val);

Sec_Result SecAsn1KC_AddAttrLong(Sec_Asn1KC* kc, const char* key, int64_t val);

Sec_Result SecAsn1KC_AddAttrInt64(Sec_Asn1KC* kc, const char* key, int64_t val);

Sec_Result SecAsn1KC_AddAttrString(Sec_Asn1KC* kc, const char* key, const char* val);

Sec_Result SecAsn1KC_AddAttrBuffer(Sec_Asn1KC* kc, const char* key, void* buf, SEC_SIZE buf_len);

Sec_Result SecAsn1KC_GetAttrUlong(Sec_Asn1KC* kc, const char* key, uint64_t* val);

Sec_Result SecAsn1KC_GetAttrUint64(Sec_Asn1KC* kc, const char* key, uint64_t* val);

Sec_Result SecAsn1KC_GetAttrLong(Sec_Asn1KC* kc, const char* key, int64_t* val);

Sec_Result SecAsn1KC_GetAttrInt64(Sec_Asn1KC* kc, const char* key, int64_t* val);

Sec_Result SecAsn1KC_GetAttrBuffer(Sec_Asn1KC* kc, const char* key, SEC_BYTE* buffer, SEC_SIZE buffer_len,
        SEC_SIZE* written);

Sec_Result SecAsn1KC_GetAttrString(Sec_Asn1KC* kc, const char* key, char* buffer, SEC_SIZE buffer_len,
        SEC_SIZE* written);

#ifdef __cplusplus
}
#endif

#endif

#endif /* SEC_SECURITY_ASN1KC_H_ */
