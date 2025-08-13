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
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClAes.h>

#include <mcuxClSession.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClCipher_Internal.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <internal/mcuxClCipherModes_Sgi_Aes_Iv.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ctr, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ctr(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut,
  uint32_t* const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ctr);

  /* Higher level caller is responsible for bound checking */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(*pOutLength, 0u, UINT32_MAX - inLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inLength, 1u, UINT32_MAX - *pOutLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)

  uint32_t outOffset = 0u;

  // number of full blocks
  uint32_t numFullBlocks  = inLength / MCUXCLAES_BLOCK_SIZE;
  // length of the last block, will be 0 < lastBlockLength <= MCUXCLAES_BLOCK_SIZE (for an inLength > 0)
  uint32_t lastBlockLength = (0u == numFullBlocks ) ? (inLength % MCUXCLAES_BLOCK_SIZE) : MCUXCLAES_BLOCK_SIZE;
  // number of SGI operations, including process of the last block if not full
  const uint32_t numOperations = (MCUXCLAES_BLOCK_SIZE == lastBlockLength) ? numFullBlocks  : MCUXCLCORE_NUM_OF_WORDS_CEIL(MCUXCLAES_BLOCK_SIZE, lastBlockLength);
  /* numOperations cannot be 0U */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(numOperations, 1U, UINT32_MAX, MCUXCLCIPHER_STATUS_INVALID_INPUT)

  /* Record the number of operations plus the SGI COUNT for DI protection. */
  MCUX_CSSL_ANALYSIS_START_PATTERN_SC_INTEGER_OVERFLOW()
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
  MCUX_CSSL_FP_FUNCTION_CALL(currCount, mcuxClSgi_Drv_getCount());
  const uint32_t sgiCount = numOperations + currCount;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SC_INTEGER_OVERFLOW()

  const uint32_t sgiCountOverflow = sgiCount & 0xFFFF0000u; // since SGI_COUNT is 16-bit register, save the possibly overflowed value and use it in DI_EXPUNGE at the end
  MCUX_CSSL_DI_RECORD(sgiCount, sgiCount);

  /* SREQI_BCIPHER_8 - Balance the block loads to SGI DATIN, i.e. the calls to mcuxClSgi_Utils_load128BitBlock */
  MCUX_CSSL_ANALYSIS_START_PATTERN_SC_INTEGER_OVERFLOW()
  uint32_t sumOfOffsets = (MCUXCLAES_BLOCK_SIZE / 2u) * (numOperations - 1u) * numOperations;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SC_INTEGER_OVERFLOW()
  // sumOfOffsets = MCUXCLAES_BLOCK_SIZE * (0 + 1 + 2 + .. + (numOperations-1))
  //              = MCUXCLAES_BLOCK_SIZE * ((numOperations-1) * numOperations) / 2
  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, sumOfOffsets);
  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, numOperations * (uint32_t)pIn);
  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, numOperations * MCUXCLAES_BLOCK_SIZE);
  MCUX_CSSL_ANALYSIS_START_PATTERN_SC_INTEGER_OVERFLOW()
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
  uint32_t sumOfAddresses = (((numOperations - 1u) >> 1u) + 1u) * (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET);
  sumOfAddresses += (((numOperations - 1u) >> 1u) + ((numOperations - 1u) % 2u)) * (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN2_OFFSET);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SC_INTEGER_OVERFLOW()
  // sumOfAddresses = the sum of sfr addresses for i=0,1,...,(numOperations -1)
  // where for even indices we add the address of MCUXCLSGI_DRV_DATIN0_OFFSET and
  // for odd indices we add MCUXCLSGI_DRV_DATIN2_OFFSET
  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, sumOfAddresses);

  /* SREQI_BCIPHER_8 - Balance DI for copyOutFunction calls */
  MCUX_CSSL_DI_RECORD(copyOutParams, sumOfOffsets);
  MCUX_CSSL_DI_RECORD(copyOutParams, numOperations * (uint32_t)pOut);
  MCUX_CSSL_DI_RECORD(copyOutParams, numOperations * (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET));
  MCUX_CSSL_DI_RECORD(copyOutParams, (numOperations - 1u) * MCUXCLAES_BLOCK_SIZE);
  MCUX_CSSL_DI_RECORD(copyOutParams, lastBlockLength);

  /* Balance DI for mcuxClSgi_Drv_incrementData calls */
  MCUX_CSSL_DI_RECORD(incLength, pWa->ctrSize * numOperations);

  // Process the first block, which may be smaller than MCUXCLAES_BLOCK_SIZE
  // Copy input to SGI
  if(inLength < MCUXCLAES_BLOCK_SIZE)
  {
      MCUX_CSSL_DI_RECORD(sgiLoadBuffer, inLength - MCUXCLAES_BLOCK_SIZE + pWa->sgiWa.paddingBuff); /* balancing already recorded parametes */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load_notFull128Block_buffer));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load_notFull128Block_buffer(MCUXCLSGI_DRV_DATIN0_OFFSET, pIn, inLength, pWa->sgiWa.paddingBuff));
  }
  else
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, pIn));
  }

  // start_up
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
    MCUXCLSGI_DRV_CTRL_END_UP                |
    MCUXCLSGI_DRV_CTRL_ENC                   |
    MCUXCLSGI_DRV_CTRL_INSEL_DATIN1          |
    MCUXCLSGI_DRV_CTRL_OUTSEL_RES_XOR_DATIN0 |
    pWa->sgiWa.sgiCtrlKey));

  uint32_t inOffset = MCUXCLAES_BLOCK_SIZE;
  static const uint32_t sgiInSel[2] = {MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLSGI_DRV_DATIN2_OFFSET};
  static const uint32_t sgiCfg[2]   = {MCUXCLSGI_DRV_CTRL_END_UP                |
                                       MCUXCLSGI_DRV_CTRL_ENC                   |
                                       MCUXCLSGI_DRV_CTRL_INSEL_DATIN1          |
                                       MCUXCLSGI_DRV_CTRL_OUTSEL_RES_XOR_DATIN0,

                                       MCUXCLSGI_DRV_CTRL_END_UP                |
                                       MCUXCLSGI_DRV_CTRL_ENC                   |
                                       MCUXCLSGI_DRV_CTRL_INSEL_DATIN1          |
                                       MCUXCLSGI_DRV_CTRL_OUTSEL_RES_XOR_DATIN2
                                       };

  // Increase counter value
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pWa->ctrSize, 0u, MCUXCLAES_BLOCK_SIZE, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_incrementData));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_incrementData(MCUXCLSGI_DRV_DATIN1_OFFSET + (MCUXCLAES_BLOCK_SIZE - pWa->ctrSize), pWa->ctrSize));

  /*
   * Iterate over remaining blocks. Here, every block is assumed to be of full size
   */
  for(uint32_t i = 1u; i < numFullBlocks ; ++i)
  {
    // Copy input to SGI
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(sgiInSel[i & 1u], pIn + inOffset));

    // wait for finish
    mcuxClSgi_Drv_wait();

    // Copy result to user
    MCUX_CSSL_FP_EXPECT(pWa->sgiWa.protectionToken_copyOutFunction);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pWa->sgiWa.copyOutFunction(session, pWa, pOut, outOffset, MCUXCLAES_BLOCK_SIZE));

    // start_up
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(sgiCfg[i & 1u] | pWa->sgiWa.sgiCtrlKey));

    // Increase counter value
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pWa->ctrSize, 0u, MCUXCLAES_BLOCK_SIZE, MCUXCLCIPHER_STATUS_INVALID_INPUT)
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_incrementData));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_incrementData(MCUXCLSGI_DRV_DATIN1_OFFSET + (MCUXCLAES_BLOCK_SIZE - pWa->ctrSize), pWa->ctrSize));

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("inOffset and outOffset are bounded by inLength")
    inOffset += MCUXCLAES_BLOCK_SIZE;
    outOffset += MCUXCLAES_BLOCK_SIZE;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
  }

  // wait for finish
  mcuxClSgi_Drv_wait();

  // Copy result to user - might not be a full block
  MCUX_CSSL_FP_EXPECT(pWa->sgiWa.protectionToken_copyOutFunction);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pWa->sgiWa.copyOutFunction(session, pWa, pOut, outOffset, lastBlockLength));
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("total outOffset is bounded by inLength")
  outOffset += lastBlockLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  if(NULL != pIvOut)
  {
    MCUX_CSSL_DI_RECORD(sgiStore, ((uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN1_OFFSET)) + ((uint32_t)pIvOut) + 16u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock(MCUXCLSGI_DRV_DATIN1_OFFSET, (uint8_t *)pIvOut));
  }

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(outOffset, 0u, inLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  *pOutLength += outOffset;

  /* Expunge the current value of the SGI COUNT plus the possibly overflowed value for DI protection.
     The sum is equal to the SGI COUNT in the beginning plus the number of operations. */

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
  MCUX_CSSL_FP_FUNCTION_CALL(currCount2, mcuxClSgi_Drv_getCount());
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Cannot overflow, since currCount2 < 2^16 and the lower 16 bits of sgiCountOverflow are 0.")
  uint32_t endCount = sgiCountOverflow + currCount2;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
  MCUX_CSSL_DI_EXPUNGE(sgiCount, endCount);

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Ctr, MCUXCLCIPHER_STATUS_OK);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CTR_Sgi =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  .encryptEngine                                 = mcuxClCipherModes_Ctr,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ctr),
  .decryptEngine                                 = mcuxClCipherModes_Ctr,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ctr),
  .completeAutoModeEngine                        = NULL,
  .protectionToken_completeAutoModeEngine        = 0U,
  .setupIVEncrypt                                = mcuxClCipherModes_IV,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV),
  .setupIVDecrypt                                = mcuxClCipherModes_IV,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen),
  .addPadding                                    = mcuxClPadding_addPadding_Stream,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_Stream),
  .removePadding                                 = mcuxClPadding_removePadding_Stream,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_Stream),
  .granularityEnc                                = 1u,
  .granularityDec                                = 1u
};
