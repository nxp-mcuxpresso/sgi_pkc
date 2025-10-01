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

#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>

#include <mcuxClAes.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClCipher_Internal.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <internal/mcuxClCipherModes_Sgi_Aes_Iv.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ecb)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_Ecb(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut UNUSED_PARAM,
  uint32_t* const pOutLength,
  uint32_t direction)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ecb);

  /* Higher level caller is responsible for bound checking */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(*pOutLength, 0u, UINT32_MAX - inLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inLength, 1u, UINT32_MAX - *pOutLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)

  uint32_t numFullBlocks  = inLength / MCUXCLAES_BLOCK_SIZE;

  if(0u < numFullBlocks)
  {
    uint32_t outOffset = 0u;
    /* Record the number of blocks plus the SGI COUNT for DI protection. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
    MCUX_CSSL_FP_FUNCTION_CALL(currCount, mcuxClSgi_Drv_getCount());
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("value used for SC balancing which supports unsigned overflow behaviour")
    const uint32_t sgiCount = numFullBlocks + currCount;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    const uint32_t sgiCountOverflow = sgiCount & 0xFFFF0000u; // since SGI_COUNT is 16-bit register, save the possibly overflowed value and use it in DI_EXPUNGE at the end
    MCUX_CSSL_DI_RECORD(sgiCount, sgiCount);

    /* SREQI_BCIPHER_8 - Balance the block loads to SGI DATIN, i.e. the calls to mcuxClSgi_Utils_load128BitBlock */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("value used for SC balancing which supports unsigned overflow behaviour")
    uint32_t sumOfOffsets = (MCUXCLAES_BLOCK_SIZE / 2u) * (numFullBlocks  - 1u) * numFullBlocks ;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    // sumOfOffsets = MCUXCLAES_BLOCK_SIZE * (0 + 1 + 2 + .. + (numFullBlocks -1))
    //              = MCUXCLAES_BLOCK_SIZE * ((numFullBlocks -1) * numFullBlocks ) / 2
    MCUX_CSSL_DI_RECORD(sgiLoadBuffer, sumOfOffsets);
    MCUX_CSSL_DI_RECORD(sgiLoadBuffer, numFullBlocks  * (uint32_t)pIn);
    MCUX_CSSL_DI_RECORD(sgiLoadBuffer, numFullBlocks  * MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_DI_RECORD(sgiLoadBuffer, numFullBlocks  * (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));

    /* SREQI_BCIPHER_8 - Balance DI for copyOutFunction calls */
    MCUX_CSSL_DI_RECORD(copyOutParams, sumOfOffsets);
    MCUX_CSSL_DI_RECORD(copyOutParams, numFullBlocks  * (uint32_t)pOut);
    MCUX_CSSL_DI_RECORD(copyOutParams, numFullBlocks  * (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET));
    MCUX_CSSL_DI_RECORD(copyOutParams, numFullBlocks  * MCUXCLAES_BLOCK_SIZE);

    // Copy first block of input to SGI
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, pIn));

    // start_up first block
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
      MCUXCLSGI_DRV_CTRL_END_UP        |
      direction                       |
      MCUXCLSGI_DRV_CTRL_INSEL_DATIN0  |
      MCUXCLSGI_DRV_CTRL_OUTSEL_RES    |
      pWa->sgiWa.sgiCtrlKey));

    /* Keep track of the input bytes that are already copied */
    uint32_t inOffset = MCUXCLAES_BLOCK_SIZE;

    for(uint32_t i = 1u; i < numFullBlocks ; ++i)
    {
      // during processing previous block, copy next block to the SGI
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, pIn + inOffset));

      // wait for finish
      mcuxClSgi_Drv_wait();

      // Copy result to user
      MCUX_CSSL_FP_EXPECT(pWa->sgiWa.protectionToken_copyOutFunction);
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(pWa->sgiWa.copyOutFunction(session, pWa, pOut, outOffset, MCUXCLAES_BLOCK_SIZE));

      // start_up
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
        MCUXCLSGI_DRV_CTRL_END_UP         |
        direction                       |
        MCUXCLSGI_DRV_CTRL_AES_NO_KL     |
        MCUXCLSGI_DRV_CTRL_INSEL_DATIN0  |
        MCUXCLSGI_DRV_CTRL_OUTSEL_RES    |
        pWa->sgiWa.sgiCtrlKey));

      /* Keep track of the input/output bytes that are already copied */
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("total outOffset / inOffset is bounded by inLength")
      inOffset += MCUXCLAES_BLOCK_SIZE;
      outOffset += MCUXCLAES_BLOCK_SIZE;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    // wait for finish
    mcuxClSgi_Drv_wait();

    // Copy result to user
    MCUX_CSSL_FP_EXPECT(pWa->sgiWa.protectionToken_copyOutFunction);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pWa->sgiWa.copyOutFunction(session, pWa, pOut, outOffset, MCUXCLAES_BLOCK_SIZE));
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("total outOffset is bounded by inLength")
    outOffset += MCUXCLAES_BLOCK_SIZE;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(outOffset, 0u, inLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)
    //Update number of data that was copied
    *pOutLength += outOffset;

    /* Expunge the current value of the SGI COUNT plus the possibly overflowed value for DI protection.
      The sum is equal to the SGI COUNT in the beginning plus the number of full blocks. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
    MCUX_CSSL_FP_FUNCTION_CALL(currCount2, mcuxClSgi_Drv_getCount());
    uint32_t endCount = sgiCountOverflow + currCount2;
    MCUX_CSSL_DI_EXPUNGE(sgiCount, endCount);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_Ecb);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ecb_Enc, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ecb_Enc(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut UNUSED_PARAM,
  uint32_t* const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ecb_Enc);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_Ecb(session, pWa, pIn, pOut, inLength, pIvOut, pOutLength, MCUXCLSGI_DRV_CTRL_ENC));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Ecb_Enc, MCUXCLCIPHER_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ecb_Dec, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ecb_Dec(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut UNUSED_PARAM,
  uint32_t* const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ecb_Dec);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_Ecb(session, pWa, pIn, pOut, inLength, pIvOut, pOutLength, MCUXCLSGI_DRV_CTRL_DEC));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Ecb_Dec, MCUXCLCIPHER_STATUS_OK);
}


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_NoPadding_Sgi =
{
  .encryptEngine                                 = mcuxClCipherModes_Ecb_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Ecb_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_Dec),
  .completeAutoModeEngine                        = NULL,
  .protectionToken_completeAutoModeEngine        = 0U,
  .setupIVEncrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .setupIVDecrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen_noIv,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen_noIv),
  .addPadding                                    = mcuxClPadding_addPadding_None,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_None),
  .removePadding                                 = NULL,
  .protectionToken_removePadding                 = 0U,
  .granularityEnc                                = MCUXCLAES_BLOCK_SIZE,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method1_Sgi =
{
  .encryptEngine                                 = mcuxClCipherModes_Ecb_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Ecb_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_Dec),
  .completeAutoModeEngine                        = NULL,
  .protectionToken_completeAutoModeEngine        = 0U,
  .setupIVEncrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .setupIVDecrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen_noIv,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen_noIv),
  .addPadding                                    = mcuxClPadding_addPadding_ISO9797_1_Method1,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method1),
  .removePadding                                 = mcuxClPadding_removePadding_ISO9797_1_Method1,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_ISO9797_1_Method1),
  .granularityEnc                                = 1u,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};


const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method2_Sgi =
{
  .encryptEngine                                 = mcuxClCipherModes_Ecb_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Ecb_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_Dec),
  .completeAutoModeEngine                        = NULL,
  .protectionToken_completeAutoModeEngine        = 0U,
  .setupIVEncrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .setupIVDecrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen_noIv,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen_noIv),
  .addPadding                                    = mcuxClPadding_addPadding_ISO9797_1_Method2,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method2),
  .removePadding                                 = mcuxClPadding_removePadding_ISO9797_1_Method2,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_ISO9797_1_Method2),
  .granularityEnc                                = 1u,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingPKCS7_Sgi =
{
  .encryptEngine                                 = mcuxClCipherModes_Ecb_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Ecb_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_Dec),
  .completeAutoModeEngine                        = NULL,
  .protectionToken_completeAutoModeEngine        = 0U,
  .setupIVEncrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .setupIVDecrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen_noIv,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen_noIv),
  .addPadding                                    = mcuxClPadding_addPadding_PKCS7,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_PKCS7),
  .removePadding                                 = mcuxClPadding_removePadding_PKCS7,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_PKCS7),
  .granularityEnc                                = 1u,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
