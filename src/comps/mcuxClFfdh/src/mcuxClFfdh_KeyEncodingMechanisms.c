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
 * @file  mcuxClFfdh_KeyEncodingMechanisms.c
 * @brief mcuxClFfdh: implementation of FFDH key encoding mechanisms (load/store/flush functions)
 */

#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClKey.h>
#include <mcuxClSession.h>

#include <mcuxClFfdh_KeyEncodingMechanisms.h>

#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMemory_Copy_Reversed_Internal.h>
#include <internal/mcuxClMemory_CopySecure_Reversed_Internal.h>
#include <internal/mcuxClSession_Internal.h>


/**********************************************************/
/* FFDH key load functions                                 */
/**********************************************************/

/**
 * @brief Key load function for Ffdh private keys in plain encoding.
 *        If spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE it securely copies key->container.pData to *ppDest.
 *
 * @param[in]   session        Handle of the current session
 * @param[in]   key            Key handle that provides information to load the key
 * @param[out]  ppDest         Pointer-pointer to the destination key location
 * @param[in]   pKeyChecksums  Storing data needed for key checksum generation
 * @param[in]   spec           Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClFfdh_PrivateKeyLoad_Plain, mcuxClKey_LoadFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClFfdh_PrivateKeyLoad_Plain(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClKey_Handle_t key,
                                                          uint8_t **ppDest,
                                                          mcuxClKey_KeyChecksum_t *pKeyChecksums UNUSED_PARAM,
                                                          mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClFfdh_PrivateKeyLoad_Plain);

  /* If spec specifies to securely copy a private key in BE and convert it to LE. */
  if (MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    uint8_t *pKeyData = mcuxClKey_getKeyData(key);
    uint8_t *pDest = *ppDest;
    uint32_t keyLength = mcuxClKey_getSize(key);

    /* Record input data for mcuxClMemory_copy_secure_reversed_int() */
    MCUX_CSSL_DI_RECORD(privateKeyBELoad, pDest);
    MCUX_CSSL_DI_RECORD(privateKeyBELoad, pKeyData);
    MCUX_CSSL_DI_RECORD(privateKeyBELoad, keyLength);

    /* Securely copy the private key to *pDest, reversing its endianness */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_reversed_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_reversed_int(pDest, pKeyData, keyLength));
  }
  /* spec is not valid */
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClFfdh_PrivateKeyLoad_Plain);
}

/**
 * @brief Key load function for Ffdh public keys in plain encoding.
 *        If spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL it copies key->container.pData to *ppDest.
 *
 * @param[in]   session        Handle of the current session
 * @param[in]   key            Key handle that provides information to load the key
 * @param[out]  ppDest         Pointer-pointer to the destination key location
 * @param[in]   pKeyChecksums  Storing data needed for key checksum generation
 * @param[in]   spec           Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClFfdh_PublicKeyLoad_Plain, mcuxClKey_LoadFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClFfdh_PublicKeyLoad_Plain(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClKey_Handle_t key,
                                                          uint8_t **ppDest,
                                                          mcuxClKey_KeyChecksum_t *pKeyChecksums UNUSED_PARAM,
                                                          mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClFfdh_PublicKeyLoad_Plain);

  /* If spec specifies to copy the key data to ppDest. */
  if (MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    uint8_t *pDest = *ppDest;
    const uint8_t *pPubKeySrc = mcuxClKey_getKeyData(key);
    const uint32_t length = mcuxClKey_getSize(key); // get the length of a public key coordinate

    /* Record input data for mcuxClMemory_copy_reversed_int() */
    MCUX_CSSL_DI_RECORD(publicKeyBELoad, pDest);
    MCUX_CSSL_DI_RECORD(publicKeyBELoad, pPubKeySrc);
    MCUX_CSSL_DI_RECORD(publicKeyBELoad, length);

    /* Copy the public key to *pDest, reversing its endianness */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_reversed_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_reversed_int(pDest, pPubKeySrc, length));
  }
  /* spec is not valid */
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClFfdh_PublicKeyLoad_Plain);
}


/**********************************************************/
/* FFDH key encoding descriptors                           */
/**********************************************************/

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
/**
 * @brief Plain key encoding descriptor for Ffdh private keys.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClFfdh_EncodingDescriptor_PrivateKey_Plain = {&mcuxClFfdh_PrivateKeyLoad_Plain,
                                                                                        NULL,
                                                                                        NULL,
                                                                                        NULL,
                                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                          mcuxClFfdh_PrivateKeyLoad_Plain),
                                                                                        0u,
                                                                                        0u,
                                                                                        0u};
/**
 * @brief Plain key encoding descriptor for Ffdh public keys.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClFfdh_EncodingDescriptor_PublicKey_Plain = {&mcuxClFfdh_PublicKeyLoad_Plain,
                                                                                        NULL,
                                                                                        NULL,
                                                                                        NULL,
                                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                          mcuxClFfdh_PublicKeyLoad_Plain),
                                                                                        0u,
                                                                                        0u,
                                                                                        0u};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
