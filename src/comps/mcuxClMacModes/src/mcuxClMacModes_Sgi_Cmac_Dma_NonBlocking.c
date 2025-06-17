/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
#include <mcuxCsslAnalysis.h>

#include <mcuxClCore_Macros.h>
#include <mcuxClMac.h>
#include <mcuxClMacModes_MemoryConsumption.h>
#include <internal/mcuxClMacModes_Common_Wa.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>
#include <internal/mcuxClMacModes_Sgi_Functions.h>
#include <internal/mcuxClMacModes_Sgi_Types.h>
#include <internal/mcuxClMacModes_Sgi_Cmac.h>
#include <internal/mcuxClMacModes_Sgi_Algorithms.h>

#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClAes.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <mcuxClDma_Types.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Utils.h>
#include <internal/mcuxClDma_Utils_Sgi.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClDma_Resource.h>
#include <mcuxClBuffer.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/* CMAC with DMA, non-blocking mode */
const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_CMAC_NonBlocking =
{
  .compute = mcuxClMacModes_computeCMAC_nonBlocking,
  .protectionToken_compute =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_computeCMAC_nonBlocking),
  .handleLastBlock_oneshot = mcuxClMacModes_handleLastBlock_cmac_oneshot,
  .protectionToken_handleLastBlock_oneshot =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_handleLastBlock_cmac_oneshot),
  .init = NULL, /* no init needed */
  .update = mcuxClMacModes_updateCMAC_nonBlocking,
  .protectionToken_update =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_updateCMAC_nonBlocking),
  .finalize = mcuxClMacModes_finalizeCMAC, /* no special DMA handling needed for blocking finalize */
  .protectionToken_finalize =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeCMAC),
  .copyOut = mcuxClMacModes_CopyOutDma,
  .protectionToken_copyOut =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_CopyOutDma),
  .addPadding = mcuxClPadding_addPadding_MAC_ISO9797_1_Method2,
  .protectionToken_addPadding =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2),
};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()


/* Non-blocking CMAC compute engine */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_computeCMAC_nonBlocking, mcuxClMacModes_ComputeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_computeCMAC_nonBlocking(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t * workArea,
  mcuxClMac_Mode_t mode UNUSED_PARAM,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  uint32_t * pProcessedBytes
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_computeCMAC_nonBlocking);

  if(inLength > MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_INPUT_SIZE)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLMAC_STATUS_INVALID_PARAM);
  }

  mcuxClMac_Status_t status = MCUXCLMAC_STATUS_ERROR;

  uint32_t lastBlockLength = (0u != inLength) ? ((inLength - 1u) % MCUXCLAES_BLOCK_SIZE + 1u) : 0u; /* length of the last block */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("inLength is at least lastBlockLength long")
  uint32_t fullBlocksLength = inLength - lastBlockLength; /* length of all full blocks, except the last one (if full) */
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  /* Generate subkeys */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_CmacGenerateSubKeys));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_CmacGenerateSubKeys(session, workArea));

  /* Load all-zero IV to DATOUT (needed by AUTO mode CMAC) */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_loadZeroIV));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_loadZeroIV());

  uint32_t sgiCtrl = MCUXCLSGI_DRV_CTRL_ENC            |
                     workArea->sgiWa.sgiCtrlKey;

  uint32_t nrOfBlocks = fullBlocksLength /  MCUXCLAES_BLOCK_SIZE;
  *pProcessedBytes = nrOfBlocks * MCUXCLAES_BLOCK_SIZE;

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);

  if(1u == nrOfBlocks)
  {
    /* For only one block of data, SGI AUTO-mode is not needed. */

    /* Copy input to SGI */
    mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLBUFFER_GET(pIn));
    mcuxClDma_Utils_startTransferOneBlock(inputChannel);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));

    /* Perform crypt operation */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_CTRL_END_UP                  |
                                                      MCUXCLSGI_DRV_CTRL_INSEL_DATIN0_XOR_DATOUT | /* IV stored in DATOUT, P0 ^ IV */
                                                      MCUXCLSGI_DRV_CTRL_OUTSEL_RES              |
                                                      sgiCtrl));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    status = MCUXCLMAC_STATUS_OK;
  }
  else if(nrOfBlocks > 1u)
  {
    /* For multiple blocks, use SGI AUTO mode with handshakes, non-blocking */

    /* Configure the DMA channels */
    mcuxClDma_Utils_configureSgiInputWithHandshakes(
      session,
      MCUXCLSGI_DRV_DATIN0_OFFSET,
      MCUXCLBUFFER_GET(pIn));

    mcuxClDma_Utils_SgiInputHandshakes_writeNumberOfBlocks(session, nrOfBlocks);

    /* Enable interrupts for the completion of the input channel, and for errors. */
    mcuxClDma_Drv_enableChannelDoneInterrupts(inputChannel);
    mcuxClDma_Drv_enableErrorInterrupts(inputChannel);

    /* Enable SGI AUTO mode CBC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_CMAC));

    /* Start the operation - this will start the SGI-DMA interaction in the background, CPU is not blocked */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_startAutoModeWithHandshakes));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_startAutoModeWithHandshakes(
      sgiCtrl | MCUXCLSGI_DRV_CTRL_NO_UP,
      MCUXCLSGI_UTILS_OUTPUT_HANDSHAKE_DISABLE));

    status = MCUXCLMAC_STATUS_JOB_STARTED;
  }
  else /* nrOfBlocks = 0 */
  {
    status = MCUXCLMAC_STATUS_OK;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_computeCMAC_nonBlocking, status);
}

/* Non-blocking CMAC update engine */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_updateCMAC_nonBlocking, mcuxClMacModes_UpdateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_updateCMAC_nonBlocking(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *workArea UNUSED_PARAM,
  mcuxClMacModes_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  uint32_t * pProcessedBytes
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_updateCMAC_nonBlocking);

  if(0u == inLength)
  {
    /* Nothing to do */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_updateCMAC_nonBlocking, MCUXCLMAC_STATUS_OK);
  }

  if(inLength > MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_INPUT_SIZE)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLMAC_STATUS_INVALID_PARAM);
  }

  if(pContext->totalInput > (UINT32_MAX - inLength))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLMAC_STATUS_INVALID_PARAM);
  }
  pContext->totalInput += inLength;

  /* Local input buffer */
  MCUXCLBUFFER_DERIVE_RO(pInLocal, pIn, 0u);

  /* Setup the general SGI configuration */
  uint32_t sgiCtrl = MCUXCLSGI_DRV_CTRL_ENC            |
                     pContext->keyContext.sgiCtrlKey;

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);

  /* If context buffer has bytes, fill the rest of the context buffer with input data; copy as many bytes as possible */
  uint32_t bytesToCopy = 0u;
  if((pContext->blockBufferUsed > 0u) && (MCUXCLAES_BLOCK_SIZE != pContext->blockBufferUsed))
  {
    bytesToCopy = ((MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed) > inLength)
                    ? inLength
                    : (MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed);

    mcuxClDma_Utils_configureDataTransfer(
      inputChannel,
      MCUXCLBUFFER_GET(pInLocal),
      ((uint8_t *)pContext->blockBuffer + pContext->blockBufferUsed), bytesToCopy);
    mcuxClDma_Drv_startChannel(inputChannel);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("blockBufferUsed has an upper bound of MCUXCLAES_BLOCK_SIZE")
    pContext->blockBufferUsed += bytesToCopy;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    MCUXCLBUFFER_UPDATE(pInLocal, bytesToCopy);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Total *pProcessedBytes has an upper bound of inLength")
    *pProcessedBytes += bytesToCopy; /* keep track of bytes processed so far */
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    /* Wait for data copy to finish and check for errors */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));
  }

  /* Calculate sizes for the remaining input data */
  uint32_t remainingInputBytes = inLength - bytesToCopy;
  uint32_t lastBlockLength = (0u != remainingInputBytes) ? ((remainingInputBytes - 1u) % MCUXCLAES_BLOCK_SIZE + 1u) : 0u; /* length of the last block */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("remainingInputBytes is at least lastBlockLength long")
  uint32_t fullBlocksLength = remainingInputBytes - lastBlockLength; /* length of all remaining full blocks, except the last one (if full) */
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  /* Load the pre-tag to DATOUT */
  const uint32_t *pSrc_maskedPreTag = (const uint32_t *)pContext->maskedPreTag;
  uint32_t *pDst_sgiDatout = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t) pDst_sgiDatout);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t) pSrc_maskedPreTag);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
    pDst_sgiDatout,
    pSrc_maskedPreTag,
    16u,
    pContext->keyContext.keySeed));

   /* Process the data in the context buffer, if possible */
  if((MCUXCLAES_BLOCK_SIZE == pContext->blockBufferUsed) &&
      (remainingInputBytes > 0u) /* if block buffer is filled with the last block, leave it there to be handled during Finalize */ )
  {
    /* For only one block of data, SGI AUTO-mode is not needed. */

    /* Load the input block to DATIN0 - DMA transfer not needed because this is not a direct I/O operation.
       The block buffer is always filled with the DMA. */
    MCUX_CSSL_DI_RECORD(sgiLoad, ((uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET)) + ((uint32_t)pContext->blockBuffer) + 16u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, (uint8_t *)pContext->blockBuffer));

    /* Perform encryption */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
      sgiCtrl                                   |
      MCUXCLSGI_DRV_CTRL_END_UP                  |
      MCUXCLSGI_DRV_CTRL_INSEL_DATIN0_XOR_DATOUT | /* pre-tag stored in DATOUT, pre-tag ^ input */
      MCUXCLSGI_DRV_CTRL_OUTSEL_RES));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    pContext->blockBufferUsed = 0u;
  }

  mcuxClMac_Status_t status = MCUXCLMAC_STATUS_ERROR;

  /* Process the remaining full blocks */
  uint32_t nrOfBlocks = fullBlocksLength /  MCUXCLAES_BLOCK_SIZE;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Total *pProcessedBytes has an upper bound of inLength")
  *pProcessedBytes += fullBlocksLength; /* keep track of bytes that will be processed in this function */
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  if(1u == nrOfBlocks)
  {
    /* For only one block of data, SGI AUTO-mode is not needed. */

    /* Copy input to SGI */
    mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLBUFFER_GET(pInLocal));
    mcuxClDma_Utils_startTransferOneBlock(inputChannel);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));

    /* Perform encryption */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
      sgiCtrl                                   |
      MCUXCLSGI_DRV_CTRL_END_UP                  |
      MCUXCLSGI_DRV_CTRL_INSEL_DATIN0_XOR_DATOUT | /* pre-tag stored in DATOUT, pre-tag ^ input */
      MCUXCLSGI_DRV_CTRL_OUTSEL_RES));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    status = MCUXCLMAC_STATUS_OK;
  }
  else if(nrOfBlocks > 1u)
  {
    /* For multiple blocks, use SGI AUTO mode with handshakes. */

    /* Configure the DMA channel */
    mcuxClDma_Utils_configureSgiInputWithHandshakes(
      session,
      MCUXCLSGI_DRV_DATIN0_OFFSET,
      MCUXCLBUFFER_GET(pInLocal));

    mcuxClDma_Utils_SgiInputHandshakes_writeNumberOfBlocks(session, nrOfBlocks);

    /* Enable interrupts for the completion of the input channel, and for errors. */
    mcuxClDma_Drv_enableChannelDoneInterrupts(inputChannel);
    mcuxClDma_Drv_enableErrorInterrupts(inputChannel);

    /* Enable SGI AUTO mode CBC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_CMAC));

    /* Start the operation - this will start the SGI-DMA interaction in the background, CPU is not blocked */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_startAutoModeWithHandshakes));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_startAutoModeWithHandshakes(
      sgiCtrl | MCUXCLSGI_DRV_CTRL_NO_UP,
      MCUXCLSGI_UTILS_OUTPUT_HANDSHAKE_DISABLE));

    status = MCUXCLMAC_STATUS_JOB_STARTED;
  }
  else /* nrOfBlock = 0 */
  {
    status = MCUXCLMAC_STATUS_OK;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_updateCMAC_nonBlocking, status);
}

