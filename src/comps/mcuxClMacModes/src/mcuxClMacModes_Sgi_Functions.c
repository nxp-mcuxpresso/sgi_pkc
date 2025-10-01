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

/** @file  mcuxClMacModes_Sgi_Functions.c
 *  @brief Implementation of mcuxClMacModes functions for SGI-based modes
 */

#include <mcuxClToolchain.h>
#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxClAes.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>
#include <mcuxClMacModes.h>
#include <mcuxClResource_Types.h>

#include <internal/mcuxClCrc_Internal_Functions.h>

#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClMacModes_Common_Functions.h>
#include <internal/mcuxClMacModes_Common_Constants.h>
#include <internal/mcuxClMacModes_Common_Memory.h>
#include <internal/mcuxClMacModes_Sgi_Types.h>
#include <internal/mcuxClMacModes_Sgi_Functions.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>
#include <internal/mcuxClMacModes_Common_Wa.h>
#include <internal/mcuxClMacModes_Sgi_Cleanup.h>
#include <internal/mcuxClMemory_Clear_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_compute, mcuxClMac_ComputeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_compute(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClMac_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pMac,
  uint32_t * const pMacLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_compute);

  mcuxClMacModes_Algorithm_t pAlgo = mcuxClMacModes_castToMacModesAlgorithm(mode->common.pAlgorithm);

  /* Allocate workarea */
  uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClMacModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMacModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  mcuxClKey_KeyChecksum_t keyChecksums;
  workArea->sgiWa.pKeyChecksums = &keyChecksums;

  /* Request SGI */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key to SGI and Store configuration data in workarea*/
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, key, &(workArea->sgiWa), MCUXCLSGI_DRV_KEY0_OFFSET));

  /* Perform MAC operation */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("False positive, this parameter is unused in the underlying function")
  MCUX_CSSL_FP_FUNCTION_CALL(retCode, pAlgo->compute(
    session,
    workArea,
    mode,
    pIn,
    inLength,
    NULL /* only used for DMA driven modes */));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
  (void) retCode; /* Blocking compute functions only return OK */

  /* Output result of MAC operation to result buffer */
  uint32_t dataProcessed = (0u < inLength) ? MCUXCLMACMODES_TRUE : MCUXCLMACMODES_FALSE;
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->copyOut(session, dataProcessed, pMac, pMacLength));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_cleanupOnExit(session, NULL, key, cpuWaSizeInWords));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_compute, MCUXCLMAC_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi),
    pAlgo->protectionToken_compute,
    pAlgo->protectionToken_copyOut,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_cleanupOnExit)
  );
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_init, mcuxClMac_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_init(
  mcuxClSession_Handle_t session,
  mcuxClMac_Context_t * const pContext,
  mcuxClKey_Handle_t key
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_init);

  mcuxClMacModes_Context_t * const pCtx = mcuxClMacModes_castToMacModesContext(pContext);
  mcuxClMacModes_Algorithm_t pAlgo = mcuxClMacModes_castToMacModesAlgorithm(pCtx->common.pMode->common.pAlgorithm);

  /* Allocate workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMACMODES_INTERNAL_WASIZE);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMacModes_WorkArea_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  pWa->sgiWa.pKeyChecksums = &(pCtx->keyContext.keyChecksums);

  /* Request SGI */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key to SGI */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, key, &pWa->sgiWa, MCUXCLSGI_DRV_KEY0_OFFSET));

  /* Store configuration data in context */
  pCtx->blockBufferUsed = 0u;
  pCtx->totalInput = 0u;
  pCtx->dataProcessed = MCUXCLMACMODES_FALSE;

  /* Store key SFR masked in context */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_storeMaskedKeyInCtx_Sgi(
    session,
    key,
    &(pCtx->keyContext),
    NULL,
    MCUXCLSGI_DRV_KEY0_OFFSET,
    mcuxClKey_getSize(key)
  ));

  /* Initialize the random sfrSeed and masked pre-tag buffer in the context. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_initMaskedPreTag(pCtx));
  /* Only mcuxClMacModes_AlgorithmDescriptor_GMAC the init pointer is not NULL */
  /* pAlgo->init will be called directly in AEAD GCM, It's not called through mcuxClMacModes_init */

  /* Set context CRC */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, sizeof(mcuxClMacModes_Context_t)));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_cleanupOnExit(
    session,
    pCtx,
    NULL /* key is in context */,
    cpuWaSizeInWords));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_init,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_storeMaskedKeyInCtx_Sgi),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_initMaskedPreTag),
    MCUX_CSSL_FP_CONDITIONAL((pAlgo->init != NULL), pAlgo->protectionToken_init),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_cleanupOnExit)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_process, mcuxClMac_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_process(
  mcuxClSession_Handle_t session,
  mcuxClMac_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_process);

  mcuxClMacModes_Context_t * const pCtx = mcuxClMacModes_castToMacModesContext(pContext);

  /* Check context CRC */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pContext, sizeof(mcuxClMacModes_Context_t)));

  mcuxClMacModes_Algorithm_t pAlgo = mcuxClMacModes_castToMacModesAlgorithm(pCtx->common.pMode->common.pAlgorithm);

  /* Allocate workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLMACMODES_INTERNAL_WASIZE);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMacModes_WorkArea_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Request SGI */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key from context to SGI */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session,
                                                                   &(pCtx->keyContext),
                                                                   NULL,
                                                                   MCUXCLSGI_DRV_KEY0_OFFSET,
                                                                   MCUXCLAES_MASKED_KEY_SIZE));

  /* Call update function */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("False positive, this parameter is unused in the underlying function")

  MCUX_CSSL_FP_FUNCTION_CALL(retCode, pAlgo->update(
    session,
    pWa,
    pCtx,
    pIn,
    inLength,
    NULL /* only used for DMA driven modes */));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
  (void) retCode; /* Blocking update functions only return OK */

  /* Update context CRC */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, sizeof(mcuxClMacModes_Context_t)));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_cleanupOnExit(
    session,
    pCtx,
    NULL /* key is in context */,
    cpuWaSizeInWords
    ));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_process, MCUXCLMAC_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi),
    pAlgo->protectionToken_update,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_cleanupOnExit)
  );
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_finish, mcuxClMac_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_finish(
  mcuxClSession_Handle_t session,
  mcuxClMac_Context_t * const pContext,
  mcuxCl_Buffer_t pMac,
  uint32_t * const pMacLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_finish);

  mcuxClMacModes_Context_t * const pCtx = mcuxClMacModes_castToMacModesContext(pContext);

  /* Check context CRC */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pContext, sizeof(mcuxClMacModes_Context_t)));

  mcuxClMacModes_Algorithm_t pAlgo = mcuxClMacModes_castToMacModesAlgorithm(pCtx->common.pMode->common.pAlgorithm);

  /* For ctx clearing at the end of the function */
  MCUX_CSSL_DI_RECORD(ctx_clear, (uint32_t)pCtx);
  MCUX_CSSL_DI_RECORD(ctx_clear, sizeof(mcuxClMacModes_Context_t));

  /* Allocate workarea */
  uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClMacModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClMacModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Request SGI */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key to SGI */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session,
                                                                   &(pCtx->keyContext),
                                                                   NULL,
                                                                   MCUXCLSGI_DRV_KEY0_OFFSET,
                                                                   MCUXCLAES_MASKED_KEY_SIZE));
  workArea->sgiWa.sgiCtrlKey = pCtx->keyContext.sgiCtrlKey;

  /* Finalize MAC operation */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->finalize(
    session,
    workArea,
    pCtx));

  /* Output result of MAC operation to result buffer */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->copyOut(session, pCtx->dataProcessed, pMac, pMacLength));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_cleanupOnExit(
    session,
    pCtx,
    NULL /* key is in context */,
    cpuWaSizeInWords));

  /* SREQI_MAC_15, SREQI_MAC_17 - Clear context.
   * Clear the context after the call to mcuxClMacModes_cleanupOnExit to not loose the key information too soon. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *)pCtx, sizeof(mcuxClMacModes_Context_t)));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_finish,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi),
    pAlgo->protectionToken_finalize,
    pAlgo->protectionToken_copyOut,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_cleanupOnExit),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int)
  );
}


