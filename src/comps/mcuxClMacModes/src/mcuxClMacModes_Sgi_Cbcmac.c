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

#include <mcuxClAes.h>
#include <mcuxClBuffer.h>
#include <mcuxClKey.h>
#include <mcuxClKey_Types.h>
#include <mcuxClMac.h>
#include <mcuxClMacModes_MemoryConsumption.h>
#include <mcuxClPadding.h>
#include <mcuxClSession.h>
#include <mcuxClToolchain.h>

#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMacModes_Common_Constants.h>
#include <internal/mcuxClMacModes_Common_Memory.h>
#include <internal/mcuxClMacModes_Common_Wa.h>
#include <internal/mcuxClMacModes_Sgi_Algorithms.h>
#include <internal/mcuxClMacModes_Sgi_Cbcmac.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>
#include <internal/mcuxClMacModes_Sgi_Functions.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClPrng_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_CBCMAC_PaddingISO9797_1_Method1 = {
  .init = NULL, /* no init needed */
  .update = mcuxClMacModes_updateCBCMac,
  .protectionToken_update = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_updateCBCMac),
  .finalize = mcuxClMacModes_finalizeCBCMac,
  .protectionToken_finalize = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeCBCMac),
  .addPadding = mcuxClPadding_addPadding_ISO9797_1_Method1,
  .protectionToken_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method1),
};


MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_updateCBCMac, mcuxClMacModes_UpdateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_updateCBCMac(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *workArea,
  mcuxClMacModes_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  uint32_t * pProcessedBytes UNUSED_PARAM
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_updateCBCMac);

  if(0u < inLength)
  {
    pContext->dataProcessed = MCUXCLMACMODES_TRUE;

    if(pContext->totalInput > (UINT32_MAX - inLength))
    {
      MCUXCLSESSION_ERROR(session, MCUXCLMAC_STATUS_INVALID_PARAM);
    }
    pContext->totalInput += inLength;

    /* Configure SGI */
    uint32_t operation = MCUXCLSGI_DRV_CTRL_END_UP                  |
                         MCUXCLSGI_DRV_CTRL_INSEL_DATIN0            |
                         MCUXCLSGI_DRV_CTRL_OUTSEL_RES              |
                         MCUXCLSGI_DRV_CTRL_ENC                     |
                         pContext->keyContext.sgiCtrlKey;

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_process_preTag_calculation));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_process_preTag_calculation(
      session,
      workArea,
      pContext,
      pIn,
      inLength,
      operation));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_updateCBCMac, MCUXCLMAC_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_finalizeCBCMac, mcuxClMacModes_FinalizeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_finalizeCBCMac(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t * workArea,
  mcuxClMacModes_Context_t * const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_finalizeCBCMac);

  mcuxClMacModes_Algorithm_t pAlgo = mcuxClMacModes_castToMacModesAlgorithm(pContext->common.pMode->common.pAlgorithm);

  /* Determine length of last block of input data */
  uint32_t noOfBytesToProcess = pContext->blockBufferUsed;
  if((0u != (noOfBytesToProcess % MCUXCLAES_BLOCK_SIZE)) && (mcuxClPadding_addPadding_None == pAlgo->addPadding))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLMAC_STATUS_INVALID_PARAM);
  }

  /* Load the (masked) preTag to DATOUT */
  uint32_t *pDst_sgiDatout = (uint32_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
  const uint32_t *pSrc_maskedPreTag = (const uint32_t *)pContext->maskedPreTag;
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pDst_sgiDatout);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pSrc_maskedPreTag);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
    pDst_sgiDatout,
    pSrc_maskedPreTag,
    16u,
    pContext->keyContext.keySeed));

  /* Do padding if need */
  MCUXCLBUFFER_INIT_RO(paddingInBuffer, NULL, (uint8_t *)pContext->blockBuffer, pContext->blockBufferUsed);
  uint32_t pOutLen = 0u;
  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_addPadding);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->addPadding(
    session,
    MCUXCLAES_BLOCK_SIZE,
    paddingInBuffer,
    0,
    pContext->blockBufferUsed,
    pContext->totalInput,
    (uint8_t *)workArea->sgiWa.paddingBuff,
    &pOutLen));

  /* Process last block. */
  if(MCUXCLAES_BLOCK_SIZE == pOutLen)
  {
    uint32_t operation = MCUXCLSGI_DRV_CTRL_END_UP |
                         MCUXCLSGI_DRV_CTRL_INSEL_DATIN0 |
                         MCUXCLSGI_DRV_CTRL_OUTSEL_RES |
                         MCUXCLSGI_DRV_CTRL_ENC |
                         pContext->keyContext.sgiCtrlKey;
    /* Record load input */
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)workArea->sgiWa.paddingBuff);
    MCUX_CSSL_DI_RECORD(sgiLoad, 16u);

    /* Copy input to SGI */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, workArea->sgiWa.paddingBuff));
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      workArea,
      pContext,
      NULL,
      0u,
      0u,
      pContext->keyContext.keySeed,
      operation,
      mcuxClMacModes_finalizeEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_finalizeCBCMac);
}
