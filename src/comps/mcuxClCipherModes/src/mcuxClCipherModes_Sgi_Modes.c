/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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

/** @file  mcuxClCipherModes_EncryptDecrypt_Sgi_Modes.c
 *  @brief Definition of the SGI mode descriptors for all provided Cipher modes
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxClCipherModes_Modes.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipher_Internal.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/*
 * Encrypt/Decrypt Modes using the SGI
 */
static const mcuxClCipher_ModeFunctions_t mcuxClCipher_ModeFunctions_CipherModes = {
  .encrypt = mcuxClCipherModes_encrypt_Sgi,
  .decrypt = mcuxClCipherModes_decrypt_Sgi,
  .protection_token_encrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_encrypt_Sgi),
  .protection_token_decrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_decrypt_Sgi),
  .initEncrypt = mcuxClCipherModes_init_encrypt_Sgi,
  .initDecrypt = mcuxClCipherModes_init_decrypt_Sgi,
  .process =     mcuxClCipherModes_process_Sgi,
  .finish  =     mcuxClCipherModes_finish_Sgi,
  .protection_token_initencrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_init_encrypt_Sgi),
  .protection_token_initdecrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_init_decrypt_Sgi),
  .protection_token_process =     MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_process_Sgi),
  .protection_token_finish  =     MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_finish_Sgi),
};

static const mcuxClCipher_ModeFunctions_t mcuxClCipher_ModeFunctions_CipherModes_dmaDriven = {
  .encrypt = mcuxClCipherModes_encrypt_Sgi_dmaDriven,
  .decrypt = mcuxClCipherModes_decrypt_Sgi_dmaDriven,
  .protection_token_encrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_encrypt_Sgi_dmaDriven),
  .protection_token_decrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_decrypt_Sgi_dmaDriven),
  .initEncrypt = mcuxClCipherModes_init_encrypt_Sgi,
  .initDecrypt = mcuxClCipherModes_init_decrypt_Sgi,
  .process =     mcuxClCipherModes_process_Sgi_dmaDriven,
  .finish  =     mcuxClCipherModes_finish_Sgi_dmaDriven,
  .protection_token_initencrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_init_encrypt_Sgi),
  .protection_token_initdecrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_init_decrypt_Sgi),
  .protection_token_process =     MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_process_Sgi_dmaDriven),
  .protection_token_finish  =     MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_finish_Sgi_dmaDriven),
};

/*
 * Encrypt/Decrypt Modes using the SGI
 */
const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_NoPadding = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_ECB_NoPadding_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method1 = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method1_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method2 = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method2_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingPKCS7 = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingPKCS7_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};


const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_NoPadding_NonBlocking =
{
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_ECB_NoPadding_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method1_NonBlocking =
{
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method1_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method2_NonBlocking =
{
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method2_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingPKCS7_NonBlocking =
{
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingPKCS7_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_NoPadding = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CBC_NoPadding_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method1 = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method1_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method2 = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method2_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingPKCS7 = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingPKCS7_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_NoPadding_NonBlocking =
{
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CBC_NoPadding_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method1_NonBlocking =
{
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method1_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method2_NonBlocking =
{
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method2_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingPKCS7_NonBlocking =
{
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingPKCS7_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CTR = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CTR_Sgi
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};

const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CTR_NonBlocking = {
  .pModeFunctions = (const void *) &mcuxClCipher_ModeFunctions_CipherModes_dmaDriven,
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the algorithm.")
  .pAlgorithm = (void *) &mcuxClCipherModes_AlgorithmDescriptor_CTR_Sgi_NonBlocking
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
};



MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
