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

/** @file  mcuxClAeadModes_Sgi_Cleanup.c
 *  @brief implementation of the cleanup functions of the mcuxClAeadModes component */


#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClAead_Constants.h>
#include <mcuxClAes.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <mcuxClSession.h>
#include <mcuxCsslDataIntegrity.h>

#include <internal/mcuxClAeadModes_Common.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClAeadModes_Common_Functions.h>
#include <internal/mcuxClAeadModes_Sgi_Cleanup.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClSgi_Utils.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClKey_Functions_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_cleanupOnMultipartExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void)
mcuxClAeadModes_cleanupOnMultipartExit(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *pContext,
  uint32_t cpuWaSizeInWords)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_cleanupOnMultipartExit);

  /* Note on SREQI_AEAD_8 for abnormal errors:
     It is not necessary to zero counter0 in contexts in case of abnormal errors,
     as the init phases of all current AEADs (GCM/CCM) properly clear/overwrite counter0 using DI-protected memory functions. */

  /* Clear the key in the context */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushKeyInContext));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushKeyInContext(session, &(pContext->cipherCtx.keyContext)));
  // TODO CLNS-17176: for GCM, flush H-key in Mac context
  // MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushSubKeyInContext));
  // MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushSubKeyInContext(session, pContext->macContext.HkeyContext));


  /* Uninitialize (and release) the SGI hardware */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Uninit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Uninit(session));

  /* Free CPU WA in Session */
  mcuxClSession_freeWords_cpuWa(session, cpuWaSizeInWords);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_cleanupOnMultipartExit);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_cleanupOnOneshotExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void)
mcuxClAeadModes_cleanupOnOneshotExit(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_cleanupOnOneshotExit);

  /* Note on SREQI_AEAD_8 for abnormal errors:
     It is not necessary to zero counter0 in contexts in case of abnormal errors,
     as the init phases of all current AEADs (GCM/CCM) properly clear/overwrite counter0 using DI-protected memory functions. */

  /* Flush the given key, if needed */
  if(MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (mcuxClKey_getLoadStatus(key) & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED))
  {
    /* Flush the key in use if it is not preloaded.
    * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_FLUSH_FP_CALLED(key));
    MCUXCLKEY_FLUSH_FP(session, key, 0U /* spec */);
  }


  /* Uninitialize (and release) the SGI hardware */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Uninit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Uninit(session));

  /* Free CPU WA in Session */
  mcuxClSession_freeWords_cpuWa(session, cpuWaSizeInWords);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_cleanupOnOneshotExit);
}
