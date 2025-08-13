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

#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClAes.h>

#include <mcuxClCipherModes_MemoryConsumption.h>

#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClCipherModes_Sgi_Cleanup.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <internal/mcuxClDma_Resource.h>

#include <internal/mcuxClCrc_Internal_Functions.h>


/**
 * @brief Function to handle OK and ERROR/FAILURE exit
 *
 * Use this function to leave functions in this file in _not_ FAULT_ATTACK cases.
 * It frees CPU workarea and uninitializes the SGI.
 *
 * @param      session          Handle for the current CL session.
 * @param      pContext         Pointer to multipart context
 * @param      key              Handle for the key.
 *                              If the key is in the context, this param shall be NULL.
 * @param[in]  cpuWaSizeInWords Number of cpu wa words to free
 */
 MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_cleanupOnExit)
 MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_cleanupOnExit(
   mcuxClSession_Handle_t session,
   mcuxClCipherModes_Context_Aes_Sgi_t *pContext,
   mcuxClKey_Handle_t key,
   uint32_t cpuWaSizeInWords
 )
 {
   MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_cleanupOnExit);

   /* Free CPU WA in Session */
   mcuxClSession_freeWords_cpuWa(session, cpuWaSizeInWords);

   /* Flush the given key, if status is not KEEPLOADED */
   if(NULL != key)
   {
     if(MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (mcuxClKey_getLoadStatus(key) & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED))
     {
       /* Flush the key in use if it is not preloaded.
       * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
       MCUXCLKEY_FLUSH_FP(session, key, 0U /* spec */);
     }
   }
   else if(NULL != pContext)
   {
     /* Flush the key in the context, if needed */
     MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushKeyInContext(session, &(pContext->keyContext)));
   }
   else
   {
     /* intentionally empty */
   }


   /* Uninitialize (and release) the SGI hardware */
   MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Uninit(session));

   MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_cleanupOnExit,
     MCUX_CSSL_FP_CONDITIONAL(((NULL != key)
         && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (mcuxClKey_getLoadStatus(key) & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED))),
       MCUXCLKEY_FLUSH_FP_CALLED(key)
     ), /* NULL != key */
     MCUX_CSSL_FP_CONDITIONAL(((NULL == key)
         && (NULL != pContext)),
       MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushKeyInContext)
     ), /* NULL != pContext */
     MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Uninit)
   );
}


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_cleanupOnExit_dmaDriven)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_cleanupOnExit_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_Context_Aes_Sgi_t *pContext,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords,
  uint32_t cleanupDmaSgi)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_cleanupOnExit_dmaDriven);

  /* Free CPU WA in Session */
  mcuxClSession_freeWords_cpuWa(session, cpuWaSizeInWords);

  if(0u != (cleanupDmaSgi & MCUXCLCIPHERMODES_CLEANUP_HW_DMA))
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_releaseInputAndOutput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_releaseInputAndOutput(session));
  }

  /* The SGI AUTO-mode might still be running if no input was processed so far
   * (can be the case, e.g., for CTR-NonBlocking mode, as it is started during the
   * pAlgo->setupIV step for this mode). We need to stop AUTO-mode here to bring the
   * SGI in non-busy state because the KEY_FLUSH (PRNG) uses the SGI.
   * If AUTO-mode is not running anymore, stopping it will do no harm. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopAndDisableAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopAndDisableAutoMode());

  if(0u != (cleanupDmaSgi & MCUXCLCIPHERMODES_CLEANUP_HW_SGI))
  {
    /* Flush the given key, if needed */
    if((NULL != key)
        && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (mcuxClKey_getLoadStatus(key) & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED))
      )
    {
      /* Flush the key in use if it is not preloaded.
      * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
      MCUX_CSSL_FP_EXPECT(MCUXCLKEY_FLUSH_FP_CALLED(key));
      MCUXCLKEY_FLUSH_FP(session, key, 0U /* spec */);
    }
    else if(NULL != pContext)
    {
      /* Flush the key in the context, if needed */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushKeyInContext));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushKeyInContext(session, &(pContext->keyContext)));
    }
    else
    {
      /* intentionally empty */
    }


    /* Uninitialize (and release) the SGI hardware */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Uninit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Uninit(session));
  }

  if (NULL != pContext)
  {
    /* Update context CRC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(&pContext->common, MCUXCLCIPHER_AES_CONTEXT_SIZE));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_handleDmaError_autoModeNonBlocking)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleDmaError_autoModeNonBlocking(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_handleDmaError_autoModeNonBlocking);

  /* Perform a dummy SGI_DATOUT read to be sure AUTO mode is wrapped-up correctly */
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 0u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 4u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 8u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 12u);

  /* Known bug in SGI AUTO mode: if AUTO_MODE.CMD is not reset to 0 , subsequent SGI operations will not work.
     Workaround: wait for SGI and reset AUTO_MODE to 0. To be removed in CLNS-7392 once fixed in HW. */
  mcuxClSgi_Drv_wait();
  mcuxClSgi_Drv_resetAutoMode();

  /* Channels do not need to be canceled / stopped. Minor loop will just not be triggered again with handshakes disabled. */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_handleDmaError_autoModeNonBlocking);
}

