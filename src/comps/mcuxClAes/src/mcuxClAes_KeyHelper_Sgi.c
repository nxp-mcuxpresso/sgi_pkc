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

/** @file  mcuxClAes_KeyHelper_Sgi.c
 *  @brief Implementations of internal functions that take care of AES key usage
 *         with the Sgi.
 */

#include <mcuxClMemory.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClAes.h>
#include <mcuxClKey.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClCrc_Internal_Functions.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClAes_Internal_Constants.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>
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
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_load));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_load(session, key, &pKeyDest, pKeyChecksums, MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE));
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

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_loadKey_Sgi);
}

// TODO CLNS-17176: Split this function according to design.
//  - Create mcuxClAes_storeSubKeyInCtx_Sgi for internal keys (mcuxClAes_SubKeyContext_Sgi_t):
//      - Shall perform the behaviour of MCUXCLAES_KEYCONTEXT_KEYDATA_MASKED_IN_CONTEXT
//      - keyOffset / keySize params not needed -> always 128-bit in KEY2
//  - Create mcuxClAes_storeKeyInCtx_Sgi for external keys (mcuxClAes_KeyContext_Sgi_t)
//      - Shall perform the behaviour of MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT
//      - keyOffset / keySize params not needed -> this information is within the key object, as the key is already loaded
/* This function implements masked key storage according to SREQI_BCIPHER_2 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_storeMaskedKeyInCtx_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_storeMaskedKeyInCtx_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAes_KeyContext_Sgi_t * const pContext,
  mcuxClAes_Workarea_Sgi_t* pWa,
  uint32_t keyOffset,
  uint32_t keySize)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_storeMaskedKeyInCtx_Sgi);

  /* Update the fields for the key in the context */
  pContext->keySize = keySize;
  if(NULL != pWa)
  {
    pContext->sgiCtrlKey = pWa->sgiCtrlKey;
  }

  /* Initialize the keyLoadStatus for all scenarios to re-use the actual handling for all cases */
  mcuxClKey_LoadStatus_t keyLoadStatus;
  if(NULL != key)
  {
    /* The key handle is valid, this key is coming from the customer.
     * Keeping this handle is needed for proper potential re-loading and flushing of the key from the SGI. */
    pContext->key = key;
    pContext->keyLocationInfo = MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT;
    if(NULL == pWa)
    {
      pContext->sgiCtrlKey = mcuxClSgi_getKeyConf(key);
    }

    keyLoadStatus = mcuxClKey_getLoadStatus(key);
  }
  else
  {
    /* Key handle is NULL, this means this key is internal (GMAC H-Key, or CMAC subkey, ..) and freshly loaded.
     * As no key handle is available, store the key slot in the context to properly flush the key from SGI later. */
    pContext->slot = mcuxClSgi_Drv_keyOffsetToSlot(keyOffset);
    pContext->keyLocationInfo = MCUXCLAES_KEYCONTEXT_KEYDATA_MASKED_IN_CONTEXT;
    if(NULL == pWa)
    {
      /* This will only be reached in case of a GMAC/GCM H-Key */
      pContext->sgiCtrlKey = MCUXCLSGI_DRV_CTRL_AES128;
    }

    keyLoadStatus = MCUXCLKEY_LOADSTATUS_LOCATION_COPRO;
  }

  /* The key is assumed to be loaded in the SGI at this point - no need to check for MCUXCLKEY_LOADSTATUS_LOCATION_COPRO. */

  /* Storing the key in the context is only possible if the key is not WRITEONLY.
   * Storing the key in the context is only necessary if the key is not KEEPLOADED. */
  if((MCUXCLKEY_LOADSTATUS_OPTIONS_WRITEONLY != (MCUXCLKEY_LOADSTATUS_OPTIONS_WRITEONLY & (keyLoadStatus)))
      && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED & (keyLoadStatus))))
  {
    /* Store the key (SGI SFR masked) in the context */
    const uint32_t *pSource = mcuxClSgi_Drv_getAddr(keyOffset);
    uint32_t *pTarget = pContext->keyMasked;

    /* Generate SFR mask seed */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word));
    MCUX_CSSL_FP_FUNCTION_CALL(sfrSeed, mcuxClPrng_generate_word());

    pContext->keySeed = sfrSeed;

    /* Record input data for mcuxClSgi_Utils_copySfrMasked() */
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pTarget);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pSource);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, keySize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(pTarget, pSource, keySize, pContext->keySeed));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_storeMaskedKeyInCtx_Sgi);
}

// TODO CLNS-17176: Split this function according to design.
//  - Create mcuxClAes_loadSubKeyFromCtx_Sgi for internal keys (mcuxClAes_SubKeyContext_Sgi_t):
//      - Shall perform the behaviour of MCUXCLAES_KEYCONTEXT_KEYDATA_MASKED_IN_CONTEXT
//      - keyOffset / keySize params not needed -> always 128-bit in KEY2
//  - Create mcuxClAes_loadKeyFromCtx_Sgi for external keys (mcuxClAes_KeyContext_Sgi_t)
//      - keySize param not needed -> this information is within the key object
//      - Shall perform the behaviour of MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT
/* This function implements masked key loading from context according to SREQI_BCIPHER_2 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_loadMaskedKeyFromCtx_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_loadMaskedKeyFromCtx_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClAes_KeyContext_Sgi_t * const pContext,
  mcuxClAes_Workarea_Sgi_t* pWa,
  uint32_t keyOffset,
  uint32_t keySize)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_loadMaskedKeyFromCtx_Sgi);

  uint32_t dstOffset;

  if(MCUXCLAES_KEYCONTEXT_KEYDATA_MASKED_IN_CONTEXT == pContext->keyLocationInfo)
  {
    /* The key is stored masked in the context, copy it to the SGI */
    const uint32_t *pSource = pContext->keyMasked;
    uint32_t *pTarget = mcuxClSgi_Drv_getAddr(keyOffset);
    uint32_t seed = pContext->keySeed;

    /* Record input data for mcuxClSgi_Utils_copySfrMasked() */
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pTarget);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pSource);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, keySize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(pTarget, pSource, keySize, seed));

    dstOffset = keyOffset;

    /* Keep track of the slot that the key was loaded to, to properly flush it later */
    pContext->slot = mcuxClSgi_Drv_keyOffsetToSlot(dstOffset);
  }
  else if(MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT == pContext->keyLocationInfo)
  {
    mcuxClKey_LoadStatus_t keyLoadStatus = mcuxClKey_getLoadStatus(pContext->key);

    /* The key handle is stored in the context, check if the key needs to be loaded */
    if(MCUXCLKEY_LOADSTATUS_NOTLOADED == keyLoadStatus)
    {
      /* Perform key loading */
      uint8_t *pKeyDest = ((uint8_t *)mcuxClSgi_Drv_getAddr(keyOffset));
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_load));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_load(session,
                                                      pContext->key,
                                                      &pKeyDest,
                                                      &(pContext->keyChecksums),
                                                      MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE));

      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("The pKeyDest points to an SGI SFR, which are always 32-bit aligned")
      dstOffset = mcuxClSgi_Drv_addressToOffset((uint32_t*)pKeyDest);
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

      /* Update the key object - this will be reset again in mcuxClAes_flushKeyInContext before exiting the Clib. */
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
      /* TODO CLNS-17176: return FAULT if this behavior is kept. Or use SESSION_FAULT? */
      MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi);
    }
  }
  else
  {
    /* Invalid flag */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi);
  }

  if(NULL != pWa)
  {
    // TODO CLNS-17176: For internal keys: always 128-bit AES keys in KEY2 register
    pWa->sgiCtrlKey = pContext->sgiCtrlKey
                      | MCUXCLSGI_DRV_CTRL_INKEYSEL(mcuxClSgi_Drv_keyOffsetToIndex(dstOffset));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi);
}

// TODO CLNS-17176: Split this function according to design.
//  - Create mcuxClAes_flushSubKey_Sgi for internal keys (mcuxClAes_SubKeyContext_Sgi_t):
//      - Shall just Flush KEY2 register (and clean the context buffer?)
//  - Create mcuxClAes_flushKeyInContext_Sgi for external keys (mcuxClAes_KeyContext_Sgi_t)
//      - Shall perform the behaviour of MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT
/* This function flushes the key in the context from SGI if said key is not KEEPLOADED (preloaded) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_flushKeyInContext)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_flushKeyInContext(
  mcuxClSession_Handle_t session,
  mcuxClAes_KeyContext_Sgi_t * const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_flushKeyInContext);

  uint32_t numKeyWords = pContext->keySize / sizeof(uint32_t);
  mcuxClKey_LoadStatus_t keyLoadStatus;
  uint32_t keySlot;

  if(MCUXCLAES_KEYCONTEXT_KEYDATA_MASKED_IN_CONTEXT == pContext->keyLocationInfo)
  {
    keySlot = pContext->slot;
    if(MCUXCLKEY_LOADOPTION_SLOT_INVALID != keySlot)
    {
      /* Usual scenario - key was loaded already when we reach the flush */
      keyLoadStatus = MCUXCLKEY_LOADSTATUS_LOCATION_COPRO;
    }
    else
    {
      /* Early exit scenario - the masked key in the context was not even loaded yet */
      keyLoadStatus = MCUXCLKEY_LOADSTATUS_NOTLOADED;
    }
  }
  else if(MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT == pContext->keyLocationInfo)
  {
    keyLoadStatus = mcuxClKey_getLoadStatus(pContext->key);
    keySlot = mcuxClKey_getLoadedKeySlot(pContext->key);
  }
  else
  {
    /* Invalid flag */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_flushKeyInContext);
  }

  if((MCUXCLKEY_LOADSTATUS_NOTLOADED != keyLoadStatus)
     && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (keyLoadStatus & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED)))
  {
    /* Flush the key in use if it is not preloaded.
     * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_flushRegisterBanks));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_flushRegisterBanks(mcuxClSgi_Drv_keySlotToOffset(keySlot), numKeyWords));

    if(MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT == pContext->keyLocationInfo)
    {
      /* Restore the initial state of the key object */
      mcuxClKey_setLoadStatus(pContext->key, MCUXCLKEY_LOADSTATUS_NOTLOADED);
      mcuxClKey_setLoadedKeySlot(pContext->key, MCUXCLKEY_LOADOPTION_SLOT_INVALID);
    }
    else
    {
      /* Mark the key as not loaded / invalid */
      pContext->slot = MCUXCLKEY_LOADOPTION_SLOT_INVALID;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_flushKeyInContext);
}
