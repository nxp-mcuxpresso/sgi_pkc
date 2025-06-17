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

#include <mcuxClToolchain.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClMac.h>
#include <internal/mcuxClMacModes_Common_Constants.h>
#include <internal/mcuxClMacModes_Sgi_Functions.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>
#include <internal/mcuxClMacModes_Sgi_Cleanup.h>

#include <internal/mcuxClSgi_Drv.h>
#include <mcuxClDma_Types.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Utils_Sgi.h>
#include <internal/mcuxClDma_Utils.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClMemory_Compare_Internal.h>
#include <internal/mcuxClMemory_CompareDPASecure_Internal.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <internal/mcuxClPrng_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_loadZeroIV)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_loadZeroIV(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_loadZeroIV);

  mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 0u, 0u);
  mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 4u, 0u);
  mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 8u, 0u);
  mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 12u, 0u);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_loadZeroIV);
}



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_CopyOutNormal, mcuxClMacModes_CopyOutputFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_CopyOutNormal(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  uint32_t dataProcessed UNUSED_PARAM,
  mcuxCl_Buffer_t pMac,
  uint32_t *const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_CopyOutNormal);

  MCUX_CSSL_DI_RECORD(sgiStoreBuffer, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiStoreBuffer, (uint32_t)pMac);
  MCUX_CSSL_DI_RECORD(sgiStoreBuffer, 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock_buffer));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock_buffer(session, MCUXCLSGI_DRV_DATOUT_OFFSET, pMac, 0u));

 *pOutLength = MCUXCLAES_BLOCK_SIZE;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_CopyOutNormal);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_CopyOutDma, mcuxClMacModes_CopyOutputFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_CopyOutDma(
  mcuxClSession_Handle_t session,
  uint32_t dataProcessed UNUSED_PARAM,
  mcuxCl_Buffer_t pMac,
  uint32_t *const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_CopyOutDma);

  /* Copy the MAC result out with the DMA */
  mcuxClSession_Channel_t channel = mcuxClSession_getDmaOutputChannel(session);
  mcuxClDma_Utils_configureSgiOutputChannel(session, MCUXCLSGI_DRV_DATOUT_OFFSET, MCUXCLBUFFER_GET(pMac));
  mcuxClDma_Utils_startTransferOneBlock(channel);

  /* Wait for data copy to finish */
  mcuxClDma_Drv_waitForChannelDone(session, channel);

  *pOutLength = MCUXCLAES_BLOCK_SIZE;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_CopyOutDma);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_initMaskedPreTag)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_initMaskedPreTag(
  mcuxClMacModes_Context_t * pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_initMaskedPreTag);
  /* Copy all-zero pre-tag to SGI DATIN0 */
  mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 0u, 0u);
  mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 4u, 0u);
  mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 8u, 0u);
  mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 12u, 0u);

  /* Store the masked initial pre-tag in the context */
  const uint32_t *pSrc_sgiDatin0 = (const uint32_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET);
  uint32_t *pDst_maskedPreTag = pContext->maskedPreTag;
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t) pDst_maskedPreTag);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t) pSrc_sgiDatin0);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
    pDst_maskedPreTag,
    pSrc_sgiDatin0,
    16u,
    /* Use already generated SFR seed from key context to mask the pretag */
    pContext->keyContext.keySeed));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_initMaskedPreTag);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_process_preTag_calculation)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_process_preTag_calculation(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *pWa,
  mcuxClMacModes_Context_t * const pContext,
  mcuxCl_InputBuffer_t pInput,
  uint32_t inputLength,
  uint32_t operation)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_process_preTag_calculation);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inputLength, 0u, UINT32_MAX - MCUXCLAES_BLOCK_SIZE, MCUXCLMAC_STATUS_INVALID_PARAM)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->blockBufferUsed, 0u, MCUXCLAES_BLOCK_SIZE, MCUXCLMAC_STATUS_INVALID_PARAM)
  if ((pContext->blockBufferUsed + inputLength) >= MCUXCLAES_BLOCK_SIZE)
  {
    uint32_t inputOffset = 0u;
    uint32_t remainingInputLength = inputLength;

    /* use bytes in blockBuffer and fill it up with input */
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, pInput);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, inputOffset);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, &((uint8_t *)pContext->blockBuffer)[pContext->blockBufferUsed]);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_secure));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_secure(
      pInput,
      inputOffset,
      &((uint8_t *)pContext->blockBuffer)[pContext->blockBufferUsed],
      MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed));

    /* adapt the input offset */
    inputOffset += MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed;
    remainingInputLength -= (MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed);

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

    MCUXCLBUFFER_INIT_RO(paddingBuf, NULL, (uint8_t *)pContext->blockBuffer, MCUXCLAES_BLOCK_SIZE);
    /* After call, result preTag is in pWa->sgiWa.secParamWa.outBuff */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      pWa,
      pContext,
      paddingBuf,
      0u,
      MCUXCLAES_BLOCK_SIZE,
      pContext->keyContext.keySeed,
      operation,
      mcuxClMacModes_updateEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_updateEngine)));

    pContext->blockBufferUsed = 0u;

    if (remainingInputLength >= MCUXCLAES_BLOCK_SIZE)
    {
      /* still some input bytes left - process full block */
      uint32_t dataBlocks = remainingInputLength / MCUXCLAES_BLOCK_SIZE;

      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
        session,
        pWa,
        pContext,
        pInput,
        inputOffset,
        dataBlocks * MCUXCLAES_BLOCK_SIZE,
        pContext->keyContext.keySeed,
        operation,
        mcuxClMacModes_updateEngine,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_updateEngine)));

      /* adapt the input offset */
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("offsets within valid pInput buffer")
      inputOffset += dataBlocks * MCUXCLAES_BLOCK_SIZE;
      remainingInputLength -= dataBlocks * MCUXCLAES_BLOCK_SIZE;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    /* Save the output to pContext->maskedPreTag for next updateEngine call */
    const uint32_t *pSrc_sgiDatout = (const uint32_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
    uint32_t *pDst_maskedPreTag = pContext->maskedPreTag;
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pDst_maskedPreTag);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pSrc_sgiDatout);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
      pDst_maskedPreTag,
      pSrc_sgiDatout,
      16u,
      pContext->keyContext.keySeed));

    if(0u != remainingInputLength)
    {
      /* copy remaining data into blockBuffer */
      MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, pInput);
      MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, inputOffset);
      MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, &((uint8_t *)pContext->blockBuffer)[0]);
      MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, remainingInputLength);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_secure));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_secure(
        pInput,
        inputOffset,
        &((uint8_t *)pContext->blockBuffer)[0],
        remainingInputLength));

      pContext->blockBufferUsed = remainingInputLength;
    }
  }
  else
  {
    /* bytes in buffer and new data is less than blockSize - save data into blockBuffer */
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, pInput);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, &((uint8_t *)pContext->blockBuffer)[pContext->blockBufferUsed]);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, inputLength);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_secure));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_secure(
      pInput,
      0u,
      &((uint8_t *)pContext->blockBuffer)[pContext->blockBufferUsed],
      inputLength));

    pContext->blockBufferUsed += inputLength;
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_process_preTag_calculation);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_engine)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_engine(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *pWa,
  mcuxClMacModes_Context_t * pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t inLength,
  uint32_t sfrSeed,
  uint32_t operation,
  mcuxClMacModes_ComputePreTagFunc_t macEngine,
  uint32_t protectionToken_macEngine)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_engine);

  mcuxClKey_KeyChecksum_t* pKeyChecksum = NULL;
  if(pContext != NULL)
  {
    pKeyChecksum = &pContext->keyContext.keyChecksums;
  }
  else
  {
    pKeyChecksum = pWa->sgiWa.pKeyChecksums;
  }

  /* For normal mac operation, don't need copy result outside */
  MCUX_CSSL_FP_EXPECT(protectionToken_macEngine);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(macEngine(pIn, inOffset, inLength, operation));

  MCUX_CSSL_FP_EXPECT(pKeyChecksum->protectionToken_VerifyFunc);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pKeyChecksum->VerifyFunc(
    NULL,
    pKeyChecksum,
    (uint8_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_KEY0_OFFSET)));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_engine);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_finalizeEngine, mcuxClMacModes_ComputePreTagFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_finalizeEngine(
  mcuxCl_InputBuffer_t pIn UNUSED_PARAM,
  uint32_t inOffset UNUSED_PARAM,
  uint32_t inLength UNUSED_PARAM,
  uint32_t operation)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_finalizeEngine);

  /* Record sgi processing blocks */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
  MCUX_CSSL_FP_FUNCTION_CALL(currCount, mcuxClSgi_Drv_getCount());
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("1u + mcuxClSgi_Drv_getCount() doesn't wrap")
  const uint32_t sgiCount = 1u + currCount;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
  const uint32_t sgiCountOverflow = sgiCount & 0xFFFF0000u; // since SGI_COUNT is 16-bit register, save the possibly overflowed value and use it in DI_EXPUNGE at the end
  MCUX_CSSL_DI_RECORD(sgiCount, sgiCount);

  operation |= MCUXCLSGI_DRV_CTRL_INSEL_DATIN0_XOR_DATOUT;
  /* encrypt last block */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(operation));
  //wait for finish
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

  /* Expunge the current value of the SGI COUNT plus the possibly overflowed value for DI protection.
     The sum is equal to the SGI COUNT in the beginning plus one. */

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
  MCUX_CSSL_FP_FUNCTION_CALL(currCount2, mcuxClSgi_Drv_getCount());
  uint32_t endCount = sgiCountOverflow + currCount2;
  MCUX_CSSL_DI_EXPUNGE(sgiCount, endCount);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_finalizeEngine);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_updateEngine, mcuxClMacModes_ComputePreTagFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_updateEngine(
  mcuxCl_InputBuffer_t pInput,
  uint32_t inOffset,
  uint32_t inLength,
  uint32_t operation)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_updateEngine);

  uint32_t numFullBlocks = inLength / MCUXCLAES_BLOCK_SIZE;

  /* Record the number of blocks plus the SGI COUNT for DI protection. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
  MCUX_CSSL_FP_FUNCTION_CALL(currCount, mcuxClSgi_Drv_getCount());
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("numFullBlocks + mcuxClSgi_Drv_getCount() doesn't wrap");
  const uint32_t sgiCount = numFullBlocks + currCount;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
  // since SGI_COUNT is 16-bit register, save the possibly overflowed value and use it in DI_EXPUNGE at the end
  const uint32_t sgiCountOverflow = sgiCount & 0xFFFF0000u;
  MCUX_CSSL_DI_RECORD(sgiCount, sgiCount);

  /* Record load buffer */
  // sumOfOffsets = MCUXCLAES_BLOCK_SIZE * (0 + 1 + 2 + .. + (numFullBlocks-1)) + inputOffset * numFullBlocks
  //              = MCUXCLAES_BLOCK_SIZE * ((numFullBlocks-1) * numFullBlocks) / 2 + inputOffset * numFullBlocks
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("value used for SC balancing which supports unsigned overflow behaviour")
  uint32_t sumOfOffsets = (MCUXCLAES_BLOCK_SIZE / 2u) * (numFullBlocks - 1u) * numFullBlocks + inOffset * numFullBlocks;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, sumOfOffsets);
  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, (numFullBlocks) * (uint32_t)pInput);
  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, (numFullBlocks) * (uint32_t)MCUXCLAES_BLOCK_SIZE);
  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, (numFullBlocks) * (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET)); // iterations in the loop load to DATIN0

  /* Load first plain block to the DATIN0 */
  /* the preTag is already loaded in the DATIN0 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock_buffer));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock_buffer(MCUXCLSGI_DRV_DATIN0_OFFSET, pInput, inOffset));

  /* Keep track of the input bytes that are already copied */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("offset within valid pIn buffer")
  inOffset += MCUXCLAES_BLOCK_SIZE;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  operation |= MCUXCLSGI_DRV_CTRL_INSEL_DATIN0_XOR_DATOUT;
  // start calc
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(operation));

  for(uint32_t i = 1u; i < numFullBlocks; ++i)
  {
    // Copy input to SGI
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("inOffset within valid pIn buffer")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock_buffer));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock_buffer(MCUXCLSGI_DRV_DATIN0_OFFSET, pInput, inOffset));

    /* Keep track of the input bytes that are already copied */
    inOffset += MCUXCLAES_BLOCK_SIZE;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    //wait for finish
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    //start_up
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(operation));
  }

  // wait for finish
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

  /* Expunge the current value of the SGI COUNT plus the possibly overflowed value for DI protection.
     The sum is equal to the SGI COUNT in the beginning plus the number of full blocks. */

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
  MCUX_CSSL_FP_FUNCTION_CALL(currCount2, mcuxClSgi_Drv_getCount());
  uint32_t endCount = sgiCountOverflow + currCount2;
  MCUX_CSSL_DI_EXPUNGE(sgiCount, endCount);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_updateEngine);
}
