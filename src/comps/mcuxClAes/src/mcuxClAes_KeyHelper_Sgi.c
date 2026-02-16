/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
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

/** @file  mcuxClAes_KeyHelper_Sgi.c
 *  @brief Implementations of internal functions that take care of AES key usage
 *         with the Sgi.
 */

#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClAes.h>
#include <mcuxClKey.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClAes_Internal_Constants.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPrng_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_loadKey_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_loadKey_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAes_Workarea_Sgi_t* pWa,
  uint32_t keyOffset)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_loadKey_Sgi);

  /* Prepare some meta data for the caller if a WA is provided */
  mcuxClKey_KeyChecksum_t* pKeyChecksums = NULL;
  if(NULL != pWa)
  {
    pKeyChecksums = pWa->pKeyChecksums;
  }

  uint32_t dstOffset;

  mcuxClKey_LoadStatus_t keyLoadStatus = mcuxClKey_getLoadStatus(key);
  if(MCUXCLKEY_LOADSTATUS_NOTLOADED == keyLoadStatus)
  {
    /* Perform key loading */
    uint8_t *pKeyDest = ((uint8_t *)mcuxClSgi_Drv_getAddr(keyOffset));
    MCUXCLKEY_LOAD_FP(session, key, &pKeyDest, pKeyChecksums, MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("The pKeyDest points to an SGI SFR, which are always 32-bit aligned")
    dstOffset = mcuxClSgi_Drv_addressToOffset((uint32_t*)pKeyDest);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

    /* Update the key object - this will be reset when flushing the key */
    mcuxClKey_setLoadedKeySlot(key, mcuxClSgi_Drv_keyOffsetToSlot(dstOffset));
    if(mcuxClSgi_Drv_isWriteOnlyKeyOffset(dstOffset))
    {
      mcuxClKey_setLoadStatus(key, MCUXCLKEY_LOADSTATUS_LOCATION_COPRO | MCUXCLKEY_LOADSTATUS_OPTIONS_WRITEONLY);
    }
    else
    {
      mcuxClKey_setLoadStatus(key, MCUXCLKEY_LOADSTATUS_LOCATION_COPRO);
    }
  }
  else if(MCUXCLKEY_LOADSTATUS_LOCATION_COPRO == (keyLoadStatus & MCUXCLKEY_LOADSTATUS_LOCATION_MASK))
  {
    /* The key is already loaded */
    dstOffset = mcuxClSgi_Drv_keySlotToOffset(mcuxClKey_getLoadedKeySlot(key));
    if(NULL != pKeyChecksums)
    {
      pKeyChecksums->VerifyFunc = key->encoding->handleKeyChecksumsFunc;
      pKeyChecksums->protectionToken_VerifyFunc = key->encoding->protectionToken_handleKeyChecksumsFunc;
    }
  }
  else
  {
    /* Not a valid key object */
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }

  if(NULL != pWa)
  {
    /* Update the SGI key CTRL information in the given workarea - set the key size and index */
    pWa->sgiCtrlKey = mcuxClSgi_getKeyTypeConf(key)
                      | MCUXCLSGI_DRV_CTRL_INKEYSEL(mcuxClSgi_Drv_keyOffsetToIndex(dstOffset));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_loadKey_Sgi,
    MCUX_CSSL_FP_CONDITIONAL((MCUXCLKEY_LOADSTATUS_NOTLOADED == keyLoadStatus),
      MCUXCLKEY_LOAD_FP_CALLED_CHECK_NULL(key))
    );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_storeKeyInCtx_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_storeKeyInCtx_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAes_KeyContext_Sgi_t * const pContext,
  mcuxClAes_Workarea_Sgi_t* pWa)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_storeKeyInCtx_Sgi);

  /* Update the fields for the key in the context */
  if(NULL != pWa)
  {
    pContext->sgiCtrlKey = pWa->sgiCtrlKey;
  }
  
  /* Generate SFR mask seed */
  MCUX_CSSL_FP_FUNCTION_CALL(sfrSeed, mcuxClPrng_generate_word());
  pContext->sfrSeed = sfrSeed;

  /* The key handle is valid, this key is coming from the customer.
    * Keeping this handle is needed for proper potential re-loading and flushing of the key from the SGI. */
  pContext->key = key;
  if(NULL == pWa)
  {
    pContext->sgiCtrlKey = mcuxClSgi_getKeyConf(key);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_storeKeyInCtx_Sgi, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_storeMaskedSubKeyInCtx_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_storeMaskedSubKeyInCtx_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClAes_HKeyContext_Sgi_t * const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_storeMaskedSubKeyInCtx_Sgi);

  /* Store the key (SGI SFR masked) in the context */
  const uint32_t *pSource = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_KEY2_OFFSET);
  uint32_t *pTarget = pContext->keyMasked;
  pContext->sgiCtrlKey = MCUXCLSGI_DRV_CTRL_AES128;

  /* Generate SFR mask seed */
  MCUX_CSSL_FP_FUNCTION_CALL(keySeed, mcuxClPrng_generate_word());
  pContext->keySeed = keySeed;

  /* Record input data for mcuxClSgi_Utils_copySfrMasked() */
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pTarget);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pSource);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, MCUXCLAES_GCM_H_KEY_SIZE);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(pTarget, pSource, MCUXCLAES_GCM_H_KEY_SIZE, pContext->keySeed));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_storeMaskedSubKeyInCtx_Sgi,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_loadKeyFromCtx_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_loadKeyFromCtx_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClAes_KeyContext_Sgi_t * const pContext,
  mcuxClAes_Workarea_Sgi_t* pWa)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_loadKeyFromCtx_Sgi);

  uint32_t dstOffset;
  mcuxClKey_LoadStatus_t keyLoadStatus = MCUXCLKEY_LOADSTATUS_NOTLOADED;

  /* The key handle is stored in the context, check if the key needs to be loaded */
  keyLoadStatus = mcuxClKey_getLoadStatus(pContext->key);
  if(MCUXCLKEY_LOADSTATUS_NOTLOADED == keyLoadStatus)
  {
    /* Perform key loading */
    uint8_t *pKeyDest = ((uint8_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_KEY0_OFFSET));
    MCUXCLKEY_LOAD_FP(
      session,
      pContext->key,
      &pKeyDest,
      &(pContext->keyChecksums),
      MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("The pKeyDest points to an SGI SFR, which are always 32-bit aligned")
    dstOffset = mcuxClSgi_Drv_addressToOffset((uint32_t*)pKeyDest);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

    /* Update the key object - this will be reset again in mcuxClAes_flushKeyInSgi before exiting the Clib. */
    mcuxClKey_setLoadedKeySlot(pContext->key, mcuxClSgi_Drv_keyOffsetToSlot(dstOffset));
    if(mcuxClSgi_Drv_isWriteOnlyKeyOffset(dstOffset))
    {
      mcuxClKey_setLoadStatus(pContext->key, MCUXCLKEY_LOADSTATUS_LOCATION_COPRO | MCUXCLKEY_LOADSTATUS_OPTIONS_WRITEONLY);
    }
    else
    {
      mcuxClKey_setLoadStatus(pContext->key, MCUXCLKEY_LOADSTATUS_LOCATION_COPRO);
    }
  }
  else if(MCUXCLKEY_LOADSTATUS_LOCATION_COPRO == (keyLoadStatus & MCUXCLKEY_LOADSTATUS_LOCATION_MASK))
  {
    /* The key is already loaded */
    dstOffset = mcuxClSgi_Drv_keySlotToOffset(mcuxClKey_getLoadedKeySlot(pContext->key));
  }
  else
  {
    /* Not a valid key object */
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }

  if(NULL != pWa)
  {
    pWa->sgiCtrlKey = pContext->sgiCtrlKey
                      | MCUXCLSGI_DRV_CTRL_INKEYSEL(mcuxClSgi_Drv_keyOffsetToIndex(dstOffset));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_loadKeyFromCtx_Sgi,
    MCUX_CSSL_FP_CONDITIONAL((
      (MCUXCLKEY_LOADSTATUS_NOTLOADED == keyLoadStatus)),
      MCUXCLKEY_LOAD_FP_CALLED_CHECK_NULL(pContext->key))
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_loadMaskedSubKeyFromCtx_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_loadMaskedSubKeyFromCtx_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClAes_HKeyContext_Sgi_t * const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_loadMaskedSubKeyFromCtx_Sgi);

  /* The key is stored masked in the context, copy it to the SGI */
  const uint32_t *pSource = pContext->keyMasked;
  uint32_t *pTarget = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_KEY2_OFFSET);
  uint32_t keySeed = pContext->keySeed;

  /* Record input data for mcuxClSgi_Utils_copySfrMasked() */
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pTarget);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pSource);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, MCUXCLAES_GCM_H_KEY_SIZE);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(pTarget, pSource, MCUXCLAES_GCM_H_KEY_SIZE, keySeed));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_loadMaskedSubKeyFromCtx_Sgi,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
}

/* This function flushes the key in the context from SGI if said key is not KEEPLOADED (preloaded) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_flushKeyInSgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_flushKeyInSgi(
  mcuxClSession_Handle_t session,
  mcuxClAes_KeyContext_Sgi_t * const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_flushKeyInSgi);

  mcuxClKey_LoadStatus_t keyLoadStatus = mcuxClKey_getLoadStatus(pContext->key);
  uint32_t keySlot = mcuxClKey_getLoadedKeySlot(pContext->key);
  uint32_t numKeyWords = mcuxClKey_getSize(pContext->key) / sizeof(uint32_t);

  if((MCUXCLKEY_LOADSTATUS_NOTLOADED != keyLoadStatus)
     && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (keyLoadStatus & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED)))
  {
    /* Record input data for mcuxClSgi_Drv_flushRegisterBanks() */
    MCUX_CSSL_DI_RECORD(sgiFlush,mcuxClSgi_Drv_keySlotToOffset(keySlot));
    MCUX_CSSL_DI_RECORD(sgiFlush,(numKeyWords * sizeof(uint32_t)));
    /* Flush the key in use if it is not preloaded.
     * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_flushRegisterBanks(mcuxClSgi_Drv_keySlotToOffset(keySlot), numKeyWords));

    /* Restore the initial state of the key object */
    mcuxClKey_setLoadStatus(pContext->key, MCUXCLKEY_LOADSTATUS_NOTLOADED);
    mcuxClKey_setLoadedKeySlot(pContext->key, MCUXCLKEY_LOADOPTION_SLOT_INVALID);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_flushKeyInSgi,
    MCUX_CSSL_FP_CONDITIONAL((
      (MCUXCLKEY_LOADSTATUS_NOTLOADED != keyLoadStatus)
        && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED & keyLoadStatus))),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_flushRegisterBanks))
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_flushSubKeyInSgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_flushSubKeyInSgi(
  mcuxClSession_Handle_t session,
  mcuxClAes_HKeyContext_Sgi_t * const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_flushSubKeyInSgi);

  /* Check if the subkey context is valid */
  if(MCUXCLSGI_DRV_CTRL_AES128 != pContext->sgiCtrlKey)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_flushSubKeyInSgi);
  }

  /* Record input data for mcuxClSgi_Drv_flushRegisterBanks() */
  MCUX_CSSL_DI_RECORD(sgiFlush, MCUXCLSGI_DRV_KEY2_OFFSET);
  MCUX_CSSL_DI_RECORD(sgiFlush, MCUXCLAES_GCM_H_KEY_SIZE);
  /* Flush the key in use if it is not preloaded.
    * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_flushRegisterBanks(MCUXCLSGI_DRV_KEY2_OFFSET, MCUXCLAES_GCM_H_KEY_SIZE_IN_WORDS));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_flushSubKeyInSgi,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_flushRegisterBanks));
}
