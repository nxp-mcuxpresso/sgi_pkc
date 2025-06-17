/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

#include <mcuxClToolchain.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClMac.h>
#include <internal/mcuxClMacModes_Common_Constants.h>
#include <internal/mcuxClMacModes_Sgi_Functions.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>
#include <internal/mcuxClMacModes_Sgi_Cleanup.h>

#include <mcuxClAes.h>
#include <internal/mcuxClSgi_Drv.h>
#include <mcuxClDma_Types.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Utils_Sgi.h>
#include <internal/mcuxClDma_Utils.h>
#include <internal/mcuxClDma_Resource.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClKey_Functions_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_cleanupOnExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_cleanupOnExit(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_Context_t *pContext,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_cleanupOnExit);

  /* Note for SREQI_MAC_17:
   * It is not necessary to explicitly clear the GMAC counter0/J0 in contexts and workareas
   * in case of abnormal errors, as the GMAC init phases for multipart and oneshot properly
   * clear/overwrite the counter0/J0 using DI-protected memory functions. */

  /* Free CPU WA in Session */
  mcuxClSession_freeWords_cpuWa(session, cpuWaSizeInWords);

  /* Flush the given key, if needed */
  if((NULL != key)
      && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (mcuxClKey_getLoadStatus(key) & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED))
    )
  {
    /* Flush the key in use if it is not preloaded.
     * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush_internal));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_flush_internal(session, key, 0U /* spec */));
  }
  else if(NULL != pContext)
  {
    /* Flush the key(s) in the context, if needed */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushKeyInContext));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushKeyInContext(session, &(pContext->keyContext)));
    // TODO CLNS-17176: for GMAC, flush H-key in context
    // MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushSubKeyInContext));
    // MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushSubKeyInContext(session, pContext->HkeyContext));
  }
  else
  {
    /* intentionally empty */
  }


  /* Uninitialize (and release) the SGI hardware */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Uninit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Uninit(session));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_cleanupOnExit);
}



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_cleanupOnExit_dmaDriven)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_cleanupOnExit_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_Context_t *pContext,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_cleanupOnExit_dmaDriven);

  /* Free CPU WA in Session */
  mcuxClSession_freeWords_cpuWa(session, cpuWaSizeInWords);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_release));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_release(session, mcuxClSession_getDmaInputChannel(session)));

  /* Flush the given key, if needed */
  if((NULL != key)
      && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (mcuxClKey_getLoadStatus(key) & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED))
    )
  {
    uint32_t numKeyWords = mcuxClKey_getSize(key) / sizeof(uint32_t);
    uint32_t keySlot = mcuxClKey_getLoadedKeySlot(key);
    /* Flush the key in use if it is not preloaded.
      * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_flushRegisterBanks));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_flushRegisterBanks(mcuxClSgi_Drv_keySlotToOffset(keySlot), numKeyWords));

    /* Restore the initial state of the key object */
    mcuxClKey_setLoadStatus(key, MCUXCLKEY_LOADSTATUS_NOTLOADED);
    mcuxClKey_setLoadedKeySlot(key, MCUXCLKEY_LOADOPTION_SLOT_INVALID);
  }
  else if(NULL != pContext)
  {
    /* Flush the key(s) in the context, if needed */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushKeyInContext));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushKeyInContext(session, &(pContext->keyContext)));
    // TODO CLNS-17176: for GMAC, flush H-key in context
    // MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushSubKeyInContext));
    // MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushSubKeyInContext(session, pContext->HkeyContext));
  }
  else
  {
    /* intentionally empty */
  }


  /* Uninitialize (and release) the SGI hardware */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Uninit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Uninit(session));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_cleanupOnExit_dmaDriven);
}

