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
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClSgi_Types.h>
#include <mcuxClAes.h>

#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClCipher_Internal.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <mcuxClDma_Types.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Utils_Sgi.h>

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_Ecb_NonBlocking_Enc, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ecb_NonBlocking_Enc(mcuxClSession_Handle_t session, mcuxClCipherModes_WorkArea_t* pWa, mcuxCl_InputBuffer_t pIn, mcuxCl_Buffer_t pOut,
                                                              uint32_t inLength, uint32_t *pIvOut, uint32_t * const pOutLength);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_Ecb_NonBlocking_Dec, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ecb_NonBlocking_Dec(mcuxClSession_Handle_t session, mcuxClCipherModes_WorkArea_t* pWa, mcuxCl_InputBuffer_t pIn, mcuxCl_Buffer_t pOut,
                                                              uint32_t inLength, uint32_t *pIvOut, uint32_t * const pOutLength);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode, mcuxClCipherModes_completeAutoModeFunc_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode(mcuxClSession_Handle_t session, mcuxClCipherModes_WorkArea_t* pWa);

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_NoPadding_Sgi_NonBlocking =
{
  .encryptEngine                                 = mcuxClCipherModes_Ecb_NonBlocking_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Ecb_NonBlocking_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_Dec),
  .completeAutoModeEngine                        = mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode),
  .setupIVEncrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .setupIVDecrypt                                = mcuxClCipherModes_No_IV,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_No_IV),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen_noIv,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen_noIv),
  .addPadding                                    = mcuxClPadding_addPadding_None,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_None),
  .removePadding                                 = mcuxClPadding_removePadding_None,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_None),
  .granularityEnc                                = MCUXCLAES_BLOCK_SIZE,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method1_Sgi_NonBlocking =
{
  .encryptEngine                                 = mcuxClCipherModes_Ecb_NonBlocking_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Ecb_NonBlocking_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_Dec),
  .completeAutoModeEngine                        = mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode),
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

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method2_Sgi_NonBlocking =
{
  .encryptEngine                                 = mcuxClCipherModes_Ecb_NonBlocking_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Ecb_NonBlocking_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_Dec),
  .completeAutoModeEngine                        = mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode),
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

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingPKCS7_Sgi_NonBlocking =
{
  .encryptEngine                                 = mcuxClCipherModes_Ecb_NonBlocking_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Ecb_NonBlocking_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_Dec),
  .completeAutoModeEngine                        = mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode),
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

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode, mcuxClCipherModes_completeAutoModeFunc_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode);

  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  /* Copy last output block from SGI */
  mcuxCl_Buffer_t pOutput = pWa->nonBlockingWa.pOut;
  mcuxClDma_Utils_configureSgiOutputChannel(session, MCUXCLSGI_DRV_DATOUT_OFFSET, MCUXCLBUFFER_GET(pOutput) + pWa->nonBlockingWa.outOffset);
  mcuxClDma_Utils_startTransferOneBlock(outputChannel);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, outputChannel));

  /* Increase output length if copy of last block was successful, and advance the output pointer */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Total outOffset/inOffset and *pOutputLength have an upper bound of inLength")
  *pWa->nonBlockingWa.pOutputLength += MCUXCLAES_BLOCK_SIZE;
  pWa->nonBlockingWa.outOffset += MCUXCLAES_BLOCK_SIZE;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_Ecb_NonBlocking_CompleteAutoMode);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ecb_NonBlocking)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ecb_NonBlocking(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut UNUSED_PARAM,
  uint32_t* const pOutLength,
  uint32_t direction)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ecb_NonBlocking);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(*pOutLength, 0u, UINT32_MAX - inLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inLength, 1u, UINT32_MAX - *pOutLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)

  if(inLength > MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_INPUT_SIZE)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
  }

  uint8_t *pOutPtr = (uint8_t *) MCUXCLBUFFER_GET(pOut);

  uint32_t nrOfBlocks = inLength / MCUXCLAES_BLOCK_SIZE;
  /* Caller ensures inLength is a non-zero multiple of MCUXCLAES_BLOCK_SIZE. */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(nrOfBlocks, 1u, UINT32_MAX, MCUXCLCIPHER_STATUS_INVALID_INPUT)

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  uint32_t sgiCtrl = direction                       |
                     pWa->sgiWa.sgiCtrlKey;

  mcuxClCipher_Status_t status;

  if(1u == nrOfBlocks)
  {
    /* For only one block of data, SGI AUTO-mode is not needed. */

    /* Copy input to SGI */
    mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN1_OFFSET, MCUXCLBUFFER_GET(pIn));
    mcuxClDma_Utils_startTransferOneBlock(inputChannel);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));

    /* Perform crypt operation */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_CTRL_END_UP                  |
                       MCUXCLSGI_DRV_CTRL_INSEL_DATIN1            |
                       MCUXCLSGI_DRV_CTRL_OUTSEL_RES              |
                       sgiCtrl));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    /* Copy output block from SGI. */
    mcuxClDma_Utils_configureSgiOutputChannel(session, MCUXCLSGI_DRV_DATOUT_OFFSET, pOutPtr);
    mcuxClDma_Utils_startTransferOneBlock(outputChannel);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, outputChannel));

    status = MCUXCLCIPHER_STATUS_OK;
    /* Increase output length if copy of last block was successful */
    *pOutLength += MCUXCLAES_BLOCK_SIZE;
  }
  else /* nrOfBlocks > 1u */
  {
    /* For multiple blocks, use SGI AUTO mode with handshakes, non-blocking */

    /* Configure the DMA channels */
    mcuxClDma_Utils_configureSgiTransferWithHandshakes(session,
                                                      MCUXCLSGI_DRV_DATIN0_OFFSET,
                                                      MCUXCLBUFFER_GET(pIn),
                                                      pOutPtr);

    mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks(session,
                                                     nrOfBlocks,
                                                     (nrOfBlocks - 1u) /* for ECB, the last output block needs to be copied seperately after SGI is stopped */
                                                     );

    /* Enable interrupts for the completion of the input channel, and for errors.
       As the output channel finishes first, there is not need to additionally enable DONE interrupts for it.
    */
    mcuxClDma_Drv_enableErrorInterrupts(inputChannel);
    mcuxClDma_Drv_enableErrorInterrupts(outputChannel);
    mcuxClDma_Drv_enableChannelDoneInterrupts(inputChannel);

    /* Enable SGI AUTO mode ECB */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_ECB));

    /* Start the operation - this will start the SGI-DMA interaction in the background, CPU is not blocked */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_startAutoModeWithHandshakes));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_startAutoModeWithHandshakes(sgiCtrl | MCUXCLSGI_DRV_CTRL_NO_UP | MCUXCLSGI_DRV_CTRL_AES_NO_KL, MCUXCLSGI_UTILS_OUTPUT_HANDSHAKE_ENABLE));

    status = MCUXCLCIPHER_STATUS_JOB_STARTED;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Ecb_NonBlocking, status);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ecb_NonBlocking_Enc, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ecb_NonBlocking_Enc(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut,
  uint32_t* const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ecb_NonBlocking_Enc);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking));
  MCUX_CSSL_FP_FUNCTION_CALL(ecbStatus, mcuxClCipherModes_Ecb_NonBlocking(session, pWa, pIn, pOut, inLength, pIvOut, pOutLength, MCUXCLSGI_DRV_CTRL_ENC));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Ecb_NonBlocking_Enc, ecbStatus);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ecb_NonBlocking_Dec, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ecb_NonBlocking_Dec(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut,
  uint32_t* const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ecb_NonBlocking_Dec);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ecb_NonBlocking));
  MCUX_CSSL_FP_FUNCTION_CALL(ecbStatus, mcuxClCipherModes_Ecb_NonBlocking(session, pWa, pIn, pOut, inLength, pIvOut, pOutLength, MCUXCLSGI_DRV_CTRL_DEC));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Ecb_NonBlocking_Dec, ecbStatus);
}

