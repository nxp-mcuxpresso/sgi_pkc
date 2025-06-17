/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

/**
 * @file  mcuxClFfdh_KeyTypes.c
 * @brief mcuxClFfdh: implementation of FFDH related key type descriptors
 */

#include <mcuxClKey.h>
#include <mcuxClFfdh.h>
#include <mcuxClFfdh_Types.h>

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClKey_Types_Internal.h>


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the key parameters.")

/* Key type structure for private and public FFDH key for RFC7919 ffdhe2048 */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe2048_Pub  =
{
  .algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLFFDH_FFDHE2048_SIZE_PUBLICKEY,
  .info = (void *) &mcuxClFfdh_domainParams_ffdhe2048,
  .plainEncoding = mcuxClFfdh_Encoding_PublicKey_Plain
};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe2048_Priv = 
{
  .algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
  .size = MCUXCLFFDH_FFDHE2048_SIZE_PRIVATEKEY,
  .info = (void *) &mcuxClFfdh_domainParams_ffdhe2048,
  .plainEncoding = mcuxClFfdh_Encoding_PrivateKey_Plain
};

/* Key type structure for private and public FFDH key for RFC7919 ffdhe3072 */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe3072_Pub  = 
{
  .algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLFFDH_FFDHE3072_SIZE_PUBLICKEY,
  .info = (void *) &mcuxClFfdh_domainParams_ffdhe3072,
  .plainEncoding = mcuxClFfdh_Encoding_PublicKey_Plain
};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe3072_Priv = {.algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PRIVATE_KEY, .size = MCUXCLFFDH_FFDHE3072_SIZE_PRIVATEKEY, .info = (void *) &mcuxClFfdh_domainParams_ffdhe3072, .plainEncoding = mcuxClFfdh_Encoding_PrivateKey_Plain};

/* Key type structure for private and public FFDH key for RFC7919 ffdhe4096 */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe4096_Pub  = 
{
  .algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLFFDH_FFDHE4096_SIZE_PUBLICKEY,
  .info = (void *) &mcuxClFfdh_domainParams_ffdhe4096,
  .plainEncoding = mcuxClFfdh_Encoding_PublicKey_Plain
};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe4096_Priv = 
{
  .algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
  .size = MCUXCLFFDH_FFDHE4096_SIZE_PRIVATEKEY,
  .info = (void *) &mcuxClFfdh_domainParams_ffdhe4096,
  .plainEncoding = mcuxClFfdh_Encoding_PrivateKey_Plain
};

/* Key type structure for private and public FFDH key for RFC7919 ffdhe6144 */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe6144_Pub  = 
{
  .algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLFFDH_FFDHE6144_SIZE_PUBLICKEY,
  .info = (void *) &mcuxClFfdh_domainParams_ffdhe6144,
  .plainEncoding = mcuxClFfdh_Encoding_PublicKey_Plain
};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe6144_Priv = {.algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PRIVATE_KEY, .size = MCUXCLFFDH_FFDHE6144_SIZE_PRIVATEKEY, .info = (void *) &mcuxClFfdh_domainParams_ffdhe6144, .plainEncoding = mcuxClFfdh_Encoding_PrivateKey_Plain};

/* Key type structure for private and public FFDH key for RFC7919 ffdhe8192 */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe8192_Pub  =
{
  .algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
  .size = MCUXCLFFDH_FFDHE8192_SIZE_PUBLICKEY,
  .info = (void *) &mcuxClFfdh_domainParams_ffdhe8192,
  .plainEncoding = mcuxClFfdh_Encoding_PublicKey_Plain
};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ffdh_ffdhe8192_Priv = {.algoId = MCUXCLKEY_ALGO_ID_FFDH + MCUXCLKEY_ALGO_ID_PRIVATE_KEY, .size = MCUXCLFFDH_FFDHE8192_SIZE_PRIVATEKEY, .info = (void *) &mcuxClFfdh_domainParams_ffdhe8192, .plainEncoding = mcuxClFfdh_Encoding_PrivateKey_Plain};

MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
