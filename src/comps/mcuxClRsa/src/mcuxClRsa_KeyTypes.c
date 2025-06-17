/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
/*                                                                          */
/* NXP Proprietary. This software is owned or controlled by NXP and may     */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/** @file  mcuxClRsa_KeyTypes.c
 *  @brief Instantiation of the key types supported by the mcuxClRsa component. */

#include <mcuxCsslAnalysis.h>
#include <mcuxClKey_Constants.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <mcuxClRsa_KeyTypes.h>
#include <internal/mcuxClRsa_Internal_Types.h>


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_Public_1024 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PUBLIC, .size = MCUXCLKEY_SIZE_1024, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PublicKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_Public_2048 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PUBLIC, .size = MCUXCLKEY_SIZE_2048, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PublicKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_Public_3072 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PUBLIC, .size = MCUXCLKEY_SIZE_3072, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PublicKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_Public_4096 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PUBLIC, .size = MCUXCLKEY_SIZE_4096, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PublicKey_Plain};

/* TODO CLNS-15273: the condition of defined(MCUXCL_FEATURE_CIPHER_RSA_SWONLY) shall be removed after SIGNATURE_RSA_SIGN or CIPHER_RSA_DECRYPT is enabled for NCCL */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivatePlain_1024 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN, .size = MCUXCLKEY_SIZE_1024, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivPlainKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivatePlain_2048 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN, .size = MCUXCLKEY_SIZE_2048, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivPlainKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivatePlain_3072 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN, .size = MCUXCLKEY_SIZE_3072, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivPlainKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivatePlain_4096 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN, .size = MCUXCLKEY_SIZE_4096, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivPlainKey_Plain};

const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivateCRT_1024 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRT, .size = MCUXCLKEY_SIZE_1024, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivCrtKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivateCRT_2048 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRT, .size = MCUXCLKEY_SIZE_2048, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivCrtKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivateCRT_3072 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRT, .size = MCUXCLKEY_SIZE_3072, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivCrtKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivateCRT_4096 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRT, .size = MCUXCLKEY_SIZE_4096, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivCrtKey_Plain};

const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivateCRT_DFA_1024 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRTDFA, .size = MCUXCLKEY_SIZE_1024, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivCrtKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivateCRT_DFA_2048 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRTDFA, .size = MCUXCLKEY_SIZE_2048, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivCrtKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivateCRT_DFA_3072 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRTDFA, .size = MCUXCLKEY_SIZE_3072, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivCrtKey_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Rsa_PrivateCRT_DFA_4096 = {.algoId = MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATECRTDFA, .size = MCUXCLKEY_SIZE_4096, .info = NULL, .plainEncoding = &mcuxClRsa_EncodingDescriptor_PrivCrtKey_Plain};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
