/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

/** @file  mcuxClKey_Encoding.c
 *  @brief Implementation of the Key encoding functions that are supported
 *  by component. */

#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClKey.h>
#include <mcuxClMemory.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClMemory_CopySecure_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClAes_KeyEncodingMechanisms_Sgi.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_KeyLoad_Plain, mcuxClKey_LoadFuncPtr_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_KeyLoad_Plain(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  uint8_t **ppDest,
  mcuxClKey_KeyChecksum_t * pKeyChecksums,
  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_KeyLoad_Plain);

  /* If spec specifies to set the key pointer to ppDest */
  if ((MCUXCLKEY_ENCODING_SPEC_ACTION_PTR == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK)))
  {
    *ppDest = mcuxClKey_getKeyData(key);
  }
  else if (MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    /* Record input data for mcuxClMemory_copy_secure_int() */
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, *ppDest);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, mcuxClKey_getKeyData(key));
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, mcuxClKey_getSize(key));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClMemory_copy_secure_int((uint8_t*)(*ppDest), mcuxClKey_getKeyData(key), mcuxClKey_getSize(key))
    );
  }
  else if (MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL== (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    /* Record input data for mcuxClMemory_copy_int() */
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int, *ppDest);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int, mcuxClKey_getKeyData(key));
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int, mcuxClKey_getSize(key));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClMemory_copy_int((uint8_t*)(*ppDest), mcuxClKey_getKeyData(key), mcuxClKey_getSize(key))
    );
  }
  else
  {
    /* spec is not valid */
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }
  if(pKeyChecksums != NULL)
  {
    pKeyChecksums->VerifyFunc = key->encoding->handleKeyChecksumsFunc;
    pKeyChecksums->protectionToken_VerifyFunc = key->encoding->protectionToken_handleKeyChecksumsFunc;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_KeyLoad_Plain);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_KeyStore_Plain, mcuxClKey_StoreFuncPtr_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_KeyStore_Plain(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClKey_Handle_t key,
  const uint8_t *pSrc,
  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_KeyStore_Plain);

  /* If spec specifies to set the key pointer to pSrc */
  if (MCUXCLKEY_ENCODING_SPEC_ACTION_PTR == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("pKeyData can not made const inside of key component as it is possible that the data changes after init due to generation/agreement/derivation of keys.");
    mcuxClKey_setKeyData(key, (uint8_t *) pSrc);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
  }
  else if (MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    uint8_t *pData = mcuxClKey_getKeyData(key);
    if(pData == pSrc)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_KeyStore_Plain);
    }
    /* Record input data for mcuxClMemory_copy_secure_int() */
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, pSrc);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, mcuxClKey_getKeyData(key));
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, mcuxClKey_getSize(key));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(pData, pSrc, mcuxClKey_getSize(key)));
  }
  else if (MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL== (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    uint8_t *pData = mcuxClKey_getKeyData(key);
    if(pData == pSrc)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_KeyStore_Plain);
    }
    /* Record input data for mcuxClMemory_copy_int() */
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int, pSrc);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int, mcuxClKey_getKeyData(key));
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int, mcuxClKey_getSize(key));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(pData, pSrc, mcuxClKey_getSize(key)));
  }
  else
  {
    /* spec is not valid */
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_KeyStore_Plain);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_KeyFlush_Plain, mcuxClKey_FlushFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_KeyFlush_Plain(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_KeyFlush_Plain);

  /* Flush the key from the loaded-to copro, based on the key type */
  if(MCUXCLKEY_ALGO_ID_AES == (mcuxClKey_getAlgoId(key) & MCUXCLKEY_ALGO_ID_ALGO_MASK))
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_keyFlush(session, key, spec));
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_KeyFlush_Plain,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_keyFlush));
  }
  else
  {
    /* spec is not valid/supported yet */
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_handleKeyChecksums_none, mcuxClKey_HandleKeyChecksums_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_handleKeyChecksums_none(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClKey_KeyChecksum_t * pKeyChecksums UNUSED_PARAM,
  uint8_t* pKey UNUSED_PARAM
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_handleKeyChecksums_none);

  // Nothing to do

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_handleKeyChecksums_none);
}


/**
 * @brief Key encoding descriptor for loading a plain key by setting the pointer in *ppDest.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClKey_EncodingDescriptor_Plain = {
  .loadFunc = &mcuxClKey_KeyLoad_Plain,
  .storeFunc = &mcuxClKey_KeyStore_Plain,
  .flushFunc = &mcuxClKey_KeyFlush_Plain,
  .handleKeyChecksumsFunc = &mcuxClKey_handleKeyChecksums_none,
  .protectionToken_loadFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_KeyLoad_Plain),
  .protectionToken_storeFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_KeyStore_Plain),
  .protectionToken_flushFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_KeyFlush_Plain),
  .protectionToken_handleKeyChecksumsFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_handleKeyChecksums_none)
};

#if 0
// TODO: define
/**
 * @brief Key encoding descriptor for Key data stored as XOR masked byte array with the mask data concatenated
 */
const mcuxClKey_EncodingDescriptor_t mcuxClKey_EncodingDescriptor_XorMasked = {NULL,
                                                                             NULL,
                                                                             NULL,
                                                                             NULL,
                                                                             0u,
                                                                             0u,
                                                                             0u,
                                                                             0u};
#endif
