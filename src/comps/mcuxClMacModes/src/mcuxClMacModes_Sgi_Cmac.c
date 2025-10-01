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

#include <mcuxClToolchain.h>

#include <mcuxClAes.h>
#include <mcuxClBuffer.h>
#include <mcuxClKey.h>
#include <mcuxClKey_Types.h>
#include <mcuxClMac.h>
#include <mcuxClMacModes_MemoryConsumption.h>
#include <mcuxClPadding.h>
#include <mcuxClSession.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMacModes_Common_Memory.h>
#include <internal/mcuxClMacModes_Common_Wa.h>
#include <internal/mcuxClMacModes_Sgi_Algorithms.h>
#include <internal/mcuxClMacModes_Sgi_Cleanup.h>
#include <internal/mcuxClMacModes_Sgi_Cmac.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>
#include <internal/mcuxClMacModes_Sgi_Functions.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClPrng_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>

/* CMAC */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_CMAC =
{
  .compute = mcuxClMacModes_computeCMAC,
  .protectionToken_compute = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_computeCMAC),
  .handleLastBlock_oneshot = NULL,
  .init = NULL, /* no init needed */
  .update = mcuxClMacModes_updateCMAC,
  .protectionToken_update = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_updateCMAC),
  .finalize = mcuxClMacModes_finalizeCMAC,
  .protectionToken_finalize = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeCMAC),
  .copyOut = mcuxClMacModes_CopyOutNormal,
  .protectionToken_copyOut = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_CopyOutNormal),
  .addPadding = mcuxClPadding_addPadding_MAC_ISO9797_1_Method2,
  .protectionToken_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2),
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

/* Helper functions */

/**
 * @brief Internal function, which shifts the buffer pointed to by pSrc by one bit to the left, conditionally
 * XORs MCUXCLMAC_AES_CMAC_RB_CONST and stores the result in a buffer pointed to by pDst.
 *
 * @param[in]  pDst       Pointer to destination buffer.
 * @param[in]  pSrc       Pointer to source buffer.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_ShiftLeftXorRb)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_ShiftLeftXorRb(uint32_t* pDst, const uint32_t* pSrc)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_ShiftLeftXorRb);
  /* multiplication GF(2) */
  /* Dst = Src << 1  */

  uint8_t constRB = 0u;

  /* Test MSB of L := AES-128(K, const_zero); if it is one, XOR with MCUXCLMACMODES_AES_CMAC_RB_CONST  */
  if(MCUXCLMACMODES_AES_CMAC_MSB_MASK == (pSrc[0] & MCUXCLMACMODES_AES_CMAC_MSB_MASK))
  {
    constRB = MCUXCLMACMODES_AES_CMAC_RB_CONST;
  }

  MCUX_CSSL_FP_LOOP_DECL(loopShiftLeftXorRb);
  for(uint32_t i = 0u; i < 3u ; ++i)
  {
    pDst[i] = (pSrc[i] << 1u) | (pSrc[i + 1u] >> ((sizeof(uint32_t) * 8u) - 1u));
    MCUX_CSSL_FP_LOOP_ITERATION(loopShiftLeftXorRb);
  }

  pDst[3] = (pSrc[3]  << 1u) ^ constRB;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_ShiftLeftXorRb,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loopShiftLeftXorRb, 3U)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_CmacGenerateSubKeys)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_CmacGenerateSubKeys(mcuxClSession_Handle_t session, mcuxClMacModes_WorkArea_t* pWa)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_CmacGenerateSubKeys);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_BE));

  uint32_t (*subKeys0)[MCUXCLMACMODES_SUBKEY_WORD_SIZE] = &pWa->algoWa.subKeys[0];
  uint32_t (*subKeys1)[MCUXCLMACMODES_SUBKEY_WORD_SIZE] = &pWa->algoWa.subKeys[1];

  /* Load zeroes to SGI input */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 0U, 0U));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 4U, 0U));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 8U, 0U));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 12U, 0U));

  //start calc
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
    MCUXCLSGI_DRV_CTRL_END_UP                  |
    MCUXCLSGI_DRV_CTRL_ENC                     |
    MCUXCLSGI_DRV_CTRL_INSEL_DATIN0            |
    MCUXCLSGI_DRV_CTRL_OUTSEL_RES              |
    pWa->sgiWa.sgiCtrlKey));

  //wait for finish
  mcuxClSgi_Drv_wait();

  /* Store result of encryption to subKey 1 */
  MCUX_CSSL_DI_RECORD(sgiStore, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiStore, (uint32_t)(*subKeys0));
  MCUX_CSSL_DI_RECORD(sgiStore, 16u);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock(MCUXCLSGI_DRV_DATOUT_OFFSET, (uint8_t *)(*subKeys0)));

  /* Shift left result of encryption to generate subKey 1 */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_ShiftLeftXorRb(*subKeys0, *subKeys0));        /* enc(0) -> multiplication GF(2) = subKey 1 */

  /* Shift left subKey 1 to generate subKey 2 */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_ShiftLeftXorRb(*subKeys1, *subKeys0));        /*   key1 -> multipMCUX_CSSL_FP_FUNCTION_CALLED_VOID(lication GF(2)) = subKey 2 */

  MCUX_CSSL_FP_FUNCTION_CALL(retSetByteOrder, mcuxClSgi_Drv_setByteOrder(MCUXCLSGI_DRV_BYTE_ORDER_LE));
  (void)retSetByteOrder;


  MCUX_CSSL_FP_EXPECT(
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_ShiftLeftXorRb),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_ShiftLeftXorRb)
  );

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_CmacGenerateSubKeys,
    (4U * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_loadWord)),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setByteOrder)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_computeCMAC, mcuxClMacModes_ComputeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_computeCMAC(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t * workArea,
  mcuxClMac_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  uint32_t * pProcessedBytes UNUSED_PARAM
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_computeCMAC);

  mcuxClMacModes_Algorithm_t pAlgo = mcuxClMacModes_castToMacModesAlgorithm(mode->common.pAlgorithm);
  if(inLength > (UINT32_MAX - MCUXCLAES_BLOCK_SIZE))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLMAC_STATUS_INVALID_PARAM);
  }

  /* Generate subkeys */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_CmacGenerateSubKeys(session, workArea));

  uint32_t operation = MCUXCLSGI_DRV_CTRL_END_UP                  |
                       MCUXCLSGI_DRV_CTRL_INSEL_DATIN0            |
                       MCUXCLSGI_DRV_CTRL_OUTSEL_RES              |
                       MCUXCLSGI_DRV_CTRL_ENC                     |
                       workArea->sgiWa.sgiCtrlKey;

  uint32_t inputOffset = 0U;
  uint32_t noOfBytesToProcess = inLength;
  uint32_t inLengthInBlocks = (inLength + (MCUXCLAES_BLOCK_SIZE - 1u)) / MCUXCLAES_BLOCK_SIZE;
  MCUX_CSSL_FP_FUNCTION_CALL(sfrSeed, mcuxClPrng_generate_word());

  /* Load all-zero IV to DATOUT */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_loadZeroIV());

  /* processing full blocks without last block*/
  if(1U < inLengthInBlocks)
  {
    uint32_t lenInBlocksLocal = (inLengthInBlocks-1U);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      workArea,
      NULL,
      pIn,
      inputOffset,
      lenInBlocksLocal * MCUXCLAES_BLOCK_SIZE,
      sfrSeed,
      operation,
      mcuxClMacModes_updateEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_updateEngine)));

    inputOffset += lenInBlocksLocal * MCUXCLAES_BLOCK_SIZE;
    noOfBytesToProcess -= lenInBlocksLocal * MCUXCLAES_BLOCK_SIZE;
  }

  /* for full blocks get subKey1 */
  uint32_t *pSubKey = workArea->algoWa.subKeys[0];

  /* Use subKey2 if padding is added */
  if(MCUXCLAES_BLOCK_SIZE > noOfBytesToProcess)
  {
    pSubKey = workArea->algoWa.subKeys[1];
  }

  /* Load subkey first, xor input data in finalizeEngine */
  MCUX_CSSL_FP_FUNCTION_CALL(retSetByteOrder, mcuxClSgi_Drv_setByteOrder((uint32_t)MCUXCLSGI_DRV_BYTE_ORDER_BE));
  (void)retSetByteOrder; /* subkeys are in big-endian, so we need to switch the SGI to BE (for the copy only) */
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)pSubKey);
  MCUX_CSSL_DI_RECORD(sgiLoad, 16u);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, (uint8_t *)pSubKey));
  MCUX_CSSL_FP_FUNCTION_CALL(sgiSetByteOrder, mcuxClSgi_Drv_setByteOrder((uint32_t)MCUXCLSGI_DRV_BYTE_ORDER_LE));
  (void)sgiSetByteOrder;

  /* Enable XOR-on-write to XOR the subkey with the last block in mcuxClMacModes_finalizeEngine() */
  MCUX_CSSL_FP_FUNCTION_CALL(ctlr2Backup, mcuxClSgi_Drv_enableXorWrite());
  (void)ctlr2Backup;

  uint32_t pOutLen = 0U;

  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(noOfBytesToProcess, 0u, MCUXCLAES_BLOCK_SIZE)
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->addPadding(
    session,
    MCUXCLAES_BLOCK_SIZE,
    pIn,
    inputOffset,
    noOfBytesToProcess,
    inLength,
    (uint8_t *)workArea->sgiWa.paddingBuff,
    &pOutLen));

  /* Record load input */
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiLoad, 16u);
  /* Process last block. */
  if(MCUXCLAES_BLOCK_SIZE == pOutLen)
  {
    /* Record load input */
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)workArea->sgiWa.paddingBuff);

    /* Copy input to SGI */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, workArea->sgiWa.paddingBuff));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableXorWrite());
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      workArea,
      NULL,
      NULL,
      0,
      0,
      sfrSeed,
      operation,
      mcuxClMacModes_finalizeEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
  }
  else /* MCUXCLAES_BLOCK_SIZE == noOfBytesToProcess */
  {
    /* Record load input */
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)pIn);
    MCUX_CSSL_DI_RECORD(sgiLoad, inputOffset);

    /* Copy input to SGI */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, pIn + inputOffset));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableXorWrite());
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      workArea,
      NULL,
      NULL,
      0,
      0,
      sfrSeed,
      operation,
      mcuxClMacModes_finalizeEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_computeCMAC, MCUXCLMAC_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_CmacGenerateSubKeys),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_loadZeroIV),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setByteOrder),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock),
    MCUX_CSSL_FP_CONDITIONAL((1U < inLengthInBlocks),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine)
    ),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setByteOrder),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableXorWrite),
    pAlgo->protectionToken_addPadding,
    MCUX_CSSL_FP_CONDITIONAL((MCUXCLAES_BLOCK_SIZE == pOutLen),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock)
    ),
    MCUX_CSSL_FP_CONDITIONAL((MCUXCLAES_BLOCK_SIZE == noOfBytesToProcess),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock)
    ),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableXorWrite),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_updateCMAC, mcuxClMacModes_UpdateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_updateCMAC(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *workArea,
  mcuxClMacModes_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  uint32_t * pProcessedBytes UNUSED_PARAM
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_updateCMAC);

  /* The `inputLen` variable is only used for FP balancing. To suppress compiler issues where FP is
  *  disabled it is used in the `inLengthFullBlocks` compuation instead of `inLength`. */
  uint32_t inputLen = inLength;

  /* Determine input size (including data accumulated in context). */
  uint32_t blockBufferUsed = pContext->blockBufferUsed;
  uint32_t inLengthFullBlocks = (inputLen + blockBufferUsed) / MCUXCLAES_BLOCK_SIZE;
  uint32_t inLengthRemainder = (inputLen + blockBufferUsed) & (MCUXCLAES_BLOCK_SIZE - 1u);

  if (0u < inLength)
  {
    if(pContext->totalInput > (UINT32_MAX - inLength))
    {
      MCUXCLSESSION_ERROR(session, MCUXCLMAC_STATUS_INVALID_PARAM);
    }
    pContext->totalInput += inLength;

    uint32_t inputOffset = 0u;
    /*
     * The last block has to be XORed with subkey.
     * Thus do not process a full last block but put it to accumulation buffer to be processed in finalize step.
     */
    if ((0u == inLengthRemainder) && (0u < inLengthFullBlocks))
    {
      inLengthFullBlocks = (inLengthFullBlocks - 1u);
      inLengthRemainder = MCUXCLAES_BLOCK_SIZE;
      if ((0u < inLengthFullBlocks) && (MCUXCLAES_BLOCK_SIZE <= inLength))
      {
        inLength -= MCUXCLAES_BLOCK_SIZE;
      }
    }
    /* Prepare operation parameters */
    uint32_t operation = MCUXCLSGI_DRV_CTRL_END_UP                  |
                         MCUXCLSGI_DRV_CTRL_INSEL_DATIN0            |
                         MCUXCLSGI_DRV_CTRL_OUTSEL_RES              |
                         MCUXCLSGI_DRV_CTRL_ENC                     |
                         pContext->keyContext.sgiCtrlKey;

    if (0u < inLengthFullBlocks)
    {
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_process_preTag_calculation(
        session,
        workArea,
        pContext,
        pIn,
        inLength,
        operation));

      inputOffset += inLength;
    }

    /* Save the last full block to context buffer */
    if ((MCUXCLAES_BLOCK_SIZE == inLengthRemainder) || (0u == inLengthFullBlocks))
    {
      MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(pContext->blockBufferUsed, 0u, MCUXCLAES_BLOCK_SIZE)
      MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(inLengthRemainder - pContext->blockBufferUsed, 0u, MCUXCLAES_BLOCK_SIZE)
      MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, pIn);
      MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, inputOffset);
      MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, &((uint8_t *)pContext->blockBuffer)[pContext->blockBufferUsed]);
      MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, inLengthRemainder - pContext->blockBufferUsed);
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_secure(
        pIn,
        inputOffset,
        &((uint8_t *)pContext->blockBuffer)[pContext->blockBufferUsed],
        inLengthRemainder - pContext->blockBufferUsed));

      pContext->blockBufferUsed = inLengthRemainder;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_updateCMAC, MCUXCLMAC_STATUS_OK,
    MCUX_CSSL_FP_CONDITIONAL(
      ((0u < inputLen) && (0u < inLengthFullBlocks)),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_process_preTag_calculation)
    ),
    MCUX_CSSL_FP_CONDITIONAL(
      ((0u < inputLen) && ((MCUXCLAES_BLOCK_SIZE == inLengthRemainder) || (0u == inLengthFullBlocks))),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_secure)
    )
  );
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_finalizeCMAC, mcuxClMacModes_FinalizeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_finalizeCMAC(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t * workArea,
  mcuxClMacModes_Context_t * const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_finalizeCMAC);

  mcuxClMacModes_Algorithm_t pAlgo = (mcuxClMacModes_Algorithm_t) pContext->common.pMode->common.pAlgorithm;

  /* Generate subkeys */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_CmacGenerateSubKeys(session, workArea));

  /* Load (masked) preTag to DATOUT */
  uint32_t *pDst_sgiDatout = (uint32_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
  const uint32_t *pSrc_maskedPreTag = (const uint32_t *)pContext->maskedPreTag;
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pDst_sgiDatout);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pSrc_maskedPreTag);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
    pDst_sgiDatout,
    pSrc_maskedPreTag,
    16u,
    pContext->keyContext.keySeed));

  /* for full blocks get subKey1 */
  uint32_t *pSubKey = workArea->algoWa.subKeys[0];

  /* Use subKey2 if padding is added */
  if(MCUXCLAES_BLOCK_SIZE > pContext->blockBufferUsed)
  {
    pSubKey = workArea->algoWa.subKeys[1];
  }
  /* Load subkey first, xor input data in finalizeEngine */
  MCUX_CSSL_FP_FUNCTION_CALL(retSetByteOrder, mcuxClSgi_Drv_setByteOrder((uint32_t)MCUXCLSGI_DRV_BYTE_ORDER_BE));
  (void)retSetByteOrder; /* subkeys are in big-endian, so we need to switch the SGI to BE (for the copy only) */
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)pSubKey);
  MCUX_CSSL_DI_RECORD(sgiLoad, 16u);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, (uint8_t *)pSubKey));
  MCUX_CSSL_FP_FUNCTION_CALL(retSetByteOrder2, mcuxClSgi_Drv_setByteOrder((uint32_t)MCUXCLSGI_DRV_BYTE_ORDER_LE));
  (void)retSetByteOrder2;

  /* Do padding if need */
  MCUXCLBUFFER_INIT_RO(paddingInBuffer, NULL, (uint8_t *)pContext->blockBuffer, pContext->blockBufferUsed);
  uint32_t pOutLen = 0u;

  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(p->blockBufferUsed, 0u, MCUXCLAES_BLOCK_SIZE)
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->addPadding(
    session,
    MCUXCLAES_BLOCK_SIZE,
    paddingInBuffer,
    0,
    pContext->blockBufferUsed,
    pContext->blockBufferUsed,
    (uint8_t *)workArea->sgiWa.paddingBuff,
    &pOutLen));

  /* Enable XOR-on-write to XOR the subkey with the last block */
  MCUX_CSSL_FP_FUNCTION_CALL(ctlr2Backup, mcuxClSgi_Drv_enableXorWrite());
  (void)ctlr2Backup;

  /* Perform encryption of the last block */
  uint32_t operation =  MCUXCLSGI_DRV_CTRL_ENC                     |
                        MCUXCLSGI_DRV_CTRL_END_UP                  |
                        MCUXCLSGI_DRV_CTRL_INSEL_DATIN0            |
                        MCUXCLSGI_DRV_CTRL_OUTSEL_RES              |
                        pContext->keyContext.sgiCtrlKey;

  /* Record load input */
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiLoad, 16u);

  /* Process last block. */
  if(MCUXCLAES_BLOCK_SIZE == pOutLen)
  {
    /* Record load input */
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)workArea->sgiWa.paddingBuff);

    /* Copy input to SGI */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, workArea->sgiWa.paddingBuff));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableXorWrite());
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      workArea,
      pContext,
      NULL,
      0,
      0,
      pContext->keyContext.keySeed,
      operation,
      mcuxClMacModes_finalizeEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
  }
  else /* MCUXCLAES_BLOCK_SIZE == pContext->blockBufferUsed */
  {
    /* Record load input */
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)paddingInBuffer);

    /* Copy input to SGI */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, paddingInBuffer));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableXorWrite());
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      workArea,
      pContext,
      NULL,
      0,
      0,
      pContext->keyContext.keySeed,
      operation,
      mcuxClMacModes_finalizeEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_finalizeCMAC,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_CmacGenerateSubKeys),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setByteOrder),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setByteOrder),
    pAlgo->protectionToken_addPadding,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableXorWrite),
    MCUX_CSSL_FP_CONDITIONAL((MCUXCLAES_BLOCK_SIZE == pOutLen),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock)
    ),
    MCUX_CSSL_FP_CONDITIONAL((MCUXCLAES_BLOCK_SIZE == pContext->blockBufferUsed),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock)
    ),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableXorWrite),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine)
  );

}

