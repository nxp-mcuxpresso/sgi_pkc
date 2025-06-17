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

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_Cbc_NonBlocking_Enc, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Cbc_NonBlocking_Enc(mcuxClSession_Handle_t session, mcuxClCipherModes_WorkArea_t* pWa, mcuxCl_InputBuffer_t pIn, mcuxCl_Buffer_t pOut,
                                                              uint32_t inLength, uint32_t *pIvOut, uint32_t * const pOutLength);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_Cbc_NonBlocking_Dec, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Cbc_NonBlocking_Dec(mcuxClSession_Handle_t session, mcuxClCipherModes_WorkArea_t* pWa, mcuxCl_InputBuffer_t pIn, mcuxCl_Buffer_t pOut,
                                                              uint32_t inLength, uint32_t *pIvOut, uint32_t * const pOutLength);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode, mcuxClCipherModes_completeAutoModeFunc_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode(mcuxClSession_Handle_t session, mcuxClCipherModes_WorkArea_t* pWa);

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_NoPadding_Sgi_NonBlocking =
{
  .encryptEngine                                 = mcuxClCipherModes_Cbc_NonBlocking_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Cbc_NonBlocking_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_Dec),
  .completeAutoModeEngine                        = mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode),
  .setupIVEncrypt                                = mcuxClCipherModes_IV_to_DATOUT_DMA,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_to_DATOUT_DMA),
  .setupIVDecrypt                                = mcuxClCipherModes_IV_AutoMode_Cbc_Dec,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_AutoMode_Cbc_Dec),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen),
  .addPadding                                    = mcuxClPadding_addPadding_None,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_None),
  .removePadding                                 = mcuxClPadding_removePadding_None,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_None),
  .granularityEnc                                = MCUXCLAES_BLOCK_SIZE,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method1_Sgi_NonBlocking =
{
  .encryptEngine                                 = mcuxClCipherModes_Cbc_NonBlocking_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Cbc_NonBlocking_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_Dec),
  .completeAutoModeEngine                        = mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode),
  .setupIVEncrypt                                = mcuxClCipherModes_IV_to_DATOUT_DMA,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_to_DATOUT_DMA),
  .setupIVDecrypt                                = mcuxClCipherModes_IV_AutoMode_Cbc_Dec,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_AutoMode_Cbc_Dec),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen),
  .addPadding                                    = mcuxClPadding_addPadding_ISO9797_1_Method1,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method1),
  .removePadding                                 = mcuxClPadding_removePadding_ISO9797_1_Method1,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_ISO9797_1_Method1),
  .granularityEnc                                = 1u,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method2_Sgi_NonBlocking =
{
  .encryptEngine                                 = mcuxClCipherModes_Cbc_NonBlocking_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Cbc_NonBlocking_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_Dec),
  .completeAutoModeEngine                        = mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode),
  .setupIVEncrypt                                = mcuxClCipherModes_IV_to_DATOUT_DMA,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_to_DATOUT_DMA),
  .setupIVDecrypt                                = mcuxClCipherModes_IV_AutoMode_Cbc_Dec,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_AutoMode_Cbc_Dec),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen),
  .addPadding                                    = mcuxClPadding_addPadding_ISO9797_1_Method2,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method2),
  .removePadding                                 = mcuxClPadding_removePadding_ISO9797_1_Method2,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_ISO9797_1_Method2),
  .granularityEnc                                = 1u,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingPKCS7_Sgi_NonBlocking =
{
  .encryptEngine                                 = mcuxClCipherModes_Cbc_NonBlocking_Enc,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_Enc),
  .decryptEngine                                 = mcuxClCipherModes_Cbc_NonBlocking_Dec,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_Dec),
  .completeAutoModeEngine                        = mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode),
  .setupIVEncrypt                                = mcuxClCipherModes_IV_to_DATOUT_DMA,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_to_DATOUT_DMA),
  .setupIVDecrypt                                = mcuxClCipherModes_IV_AutoMode_Cbc_Dec,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_AutoMode_Cbc_Dec),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen),
  .addPadding                                    = mcuxClPadding_addPadding_PKCS7,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_PKCS7),
  .removePadding                                 = mcuxClPadding_removePadding_PKCS7,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_PKCS7),
  .granularityEnc                                = 1u,
  .granularityDec                                = MCUXCLAES_BLOCK_SIZE
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

/**
 * @brief This function handle last block in auto-mode, if was more than one block.
 *
 * @param session Handle for the current CL session.
 * @param pWa pointer to a work area
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode, mcuxClCipherModes_completeAutoModeFunc_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode);

  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);

  /* Copy last output block from SGI */
  mcuxCl_Buffer_t pOutput = pWa->nonBlockingWa.pOut;
  mcuxClDma_Utils_configureSgiOutputChannel(session, MCUXCLSGI_DRV_DATOUT_OFFSET, MCUXCLBUFFER_GET(pOutput) + pWa->nonBlockingWa.outOffset);
  mcuxClDma_Utils_startTransferOneBlock(outputChannel);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, outputChannel));

  /* Increase output length if copy of last block was successful, and advance the output pointer */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Total outOffset and *pOutputLength has an upper bound of inLength")
  *pWa->nonBlockingWa.pOutputLength += MCUXCLAES_BLOCK_SIZE;
  pWa->nonBlockingWa.outOffset += MCUXCLAES_BLOCK_SIZE;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  /* Known bug in SGI AUTO mode: if AUTO_MODE.CMD is not reset to 0 here, subsequent SGI operations will not work.
     Workaround: After final result was read, wait for SGI and reset AUTO_MODE to 0. To be removed in CLNS-7392 once fixed in HW. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait()); /* Known limitation: wait for SGI busy flag to be de-asserted before overwriting AUTO mode CMD */
  mcuxClSgi_Drv_resetAutoMode();

  if(MCUXCLCIPHERMODES_DECRYPT == pWa->nonBlockingWa.direction)
  {
    /* Calculate where last input data will be stored.
    Every time DMA loads data it loads in diffrent SGI->DATIN register.
    When we put first data in DATIN0 next will be placed in DATIN1 and next in DATIN2
    DATIN0->DATIN1->DATIN2->DATIN0....
    Warning: If number of SGI DATIN register changes this might cause issues*/
    uint32_t blocksRead = (uint32_t)mcuxClDma_Drv_readMajorBeginningLoopCount(inputChannel);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Blocksread must be at least one as otherwise the automode would not have been executed")
    uint32_t ivOffset = ((blocksRead - 1u) % 3u) * 4u;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    MCUXCLSGI_UTILS_STORE128BITBLOCK_DI_BALANCED(MCUXCLSGI_DRV_DATIN0_OFFSET + (4u*ivOffset), (uint8_t *)pWa->pIV);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_Cbc_NonBlocking_CompleteAutoMode);
}

/**
 * @brief This function encrypt data in non blocking mode
 *
 * @param session Handle for the current CL session.
 * @param pWa pointer to a work area
 * @param pIn pointer to the input buffer
 * @param pOut pointer to the output buffer
 * @param inLength length of input in bytes
 * @param pIvOut pointer to the IV buffer
 * @param pOutLength pointer to the out length variable
 *
 * @return status
 */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Cbc_NonBlocking_Enc, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Cbc_NonBlocking_Enc(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut,
  uint32_t* const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Cbc_NonBlocking_Enc);

  /* Higher level caller is responsible for bound checking */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(*pOutLength, 0u, UINT32_MAX - inLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inLength, 1u, UINT32_MAX - *pOutLength, MCUXCLCIPHER_STATUS_INVALID_INPUT)

  if(inLength > MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_INPUT_SIZE)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
  }

  uint32_t remainingBlocks = inLength / MCUXCLAES_BLOCK_SIZE;
  /* Caller ensures inLength is a non-zero multiple of MCUXCLAES_BLOCK_SIZE. */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(remainingBlocks, 1u, UINT32_MAX, MCUXCLCIPHER_STATUS_INVALID_INPUT)

  uint8_t *pOutPtr = (uint8_t *) MCUXCLBUFFER_GET(pOut);

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  uint32_t sgiCtrl = MCUXCLSGI_DRV_CTRL_ENC           |
                     pWa->sgiWa.sgiCtrlKey;

  mcuxClCipher_Status_t status;

  if(1u == remainingBlocks)
  {
    /* For only one block of data, SGI AUTO-mode is not needed. */

    /* Copy input to SGI */
    mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLBUFFER_GET(pIn));
    mcuxClDma_Utils_startTransferOneBlock(inputChannel);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));

    /* Perform encryption */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
      MCUXCLSGI_DRV_CTRL_END_UP                  |
      MCUXCLSGI_DRV_CTRL_INSEL_DATIN0_XOR_DATOUT | /* IV stored in DATOUT, P0 ^ IV */
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

    /* Copy the IV to the SGI SFR that is expected to contain the IV.
       Note that DMA transfer is not needed here because this is not an I/O operation. */
    if(NULL != pIvOut)
    {
      MCUXCLSGI_UTILS_STORE128BITBLOCK_DI_BALANCED(MCUXCLSGI_DRV_DATOUT_OFFSET, (uint8_t *)pIvOut);
    }
  }
  else /* remainingBlocks > 1u */
  {
    /* For multiple blocks, use SGI AUTO mode with handshakes, non-blocking */

    /* Configure the DMA channels */
    mcuxClDma_Utils_configureSgiTransferWithHandshakes(session,
                                                      MCUXCLSGI_DRV_DATIN0_OFFSET,
                                                      MCUXCLBUFFER_GET(pIn),
                                                      pOutPtr);

    mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks(session,
                                                     remainingBlocks,
                                                     (remainingBlocks - 1u) /* for CBC, the last output block needs to be copied seperately after SGI is stopped */
                                                     );

    /* Enable interrupts for the completion of the input channel, and for errors.
       As the output channel finishes first, there is not need to additionally enable DONE interrupts for it.
    */
    mcuxClDma_Drv_enableErrorInterrupts(inputChannel);
    mcuxClDma_Drv_enableErrorInterrupts(outputChannel);
    mcuxClDma_Drv_enableChannelDoneInterrupts(inputChannel);

    /* Enable SGI AUTO mode CBC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_CBC));

    /* Start the operation - this will start the SGI-DMA interaction in the background, CPU is not blocked */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_startAutoModeWithHandshakes));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_startAutoModeWithHandshakes(sgiCtrl | MCUXCLSGI_DRV_CTRL_NO_UP, MCUXCLSGI_UTILS_OUTPUT_HANDSHAKE_ENABLE));

    status = MCUXCLCIPHER_STATUS_JOB_STARTED;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Cbc_NonBlocking_Enc, status);
}

/**
 * @brief This function decrypt data in non blocking mode
 *
 * @param session Handle for the current CL session.
 * @param pWa pointer to a work area
 * @param pIn pointer to the input buffer
 * @param pOut pointer to the output buffer
 * @param inLength length of input in bytes
 * @param pIvOut pointer to the IV buffer
 * @param pOutLength pointer to the out length variable
 *
 * @return status
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Cbc_NonBlocking_Dec, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Cbc_NonBlocking_Dec(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut,
  uint32_t* const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Cbc_NonBlocking_Dec);

  if(inLength > MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_INPUT_SIZE)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
  }

  uint32_t remainingBlocks = inLength / MCUXCLAES_BLOCK_SIZE;
  /* Caller ensures inLength is a non-zero multiple of MCUXCLAES_BLOCK_SIZE. */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(remainingBlocks, 1u, UINT32_MAX, MCUXCLCIPHER_STATUS_INVALID_INPUT)

  uint8_t *pOutPtr = (uint8_t *) MCUXCLBUFFER_GET(pOut);

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  uint32_t sgiCtrl = MCUXCLSGI_DRV_CTRL_DEC           |
                     pWa->sgiWa.sgiCtrlKey;

  mcuxClCipher_Status_t status;

  if(1u == remainingBlocks)
  {
    /* For only one block of data, SGI AUTO-mode is not needed. */

    /* Copy input to SGI */
    mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN1_OFFSET, MCUXCLBUFFER_GET(pIn));
    mcuxClDma_Utils_startTransferOneBlock(inputChannel);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));

    /* Perform decryption */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
      MCUXCLSGI_DRV_CTRL_END_UP                  |
      MCUXCLSGI_DRV_CTRL_OUTSEL_RES_XOR_DATIN2   | /* IV stored in DATIN2, IV ^ C0 */
      MCUXCLSGI_DRV_CTRL_INSEL_DATIN1            |
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
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("*pOutLength has an upper bound of inLength")
    *pOutLength += MCUXCLAES_BLOCK_SIZE;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()


    /* Copy the IV to the SGI SFR that is expected to contain the IV.
       Note that DMA transfer is not needed here because this is not an I/O operation. */
    if(NULL != pIvOut)
    {
      MCUXCLSGI_UTILS_STORE128BITBLOCK_DI_BALANCED(MCUXCLSGI_DRV_DATIN1_OFFSET, (uint8_t *)pIvOut);
    }
  }
  else /* remainingBlocks > 1u */
  {
    /* For multiple blocks, use SGI AUTO mode with handshakes, non-blocking */

    /* Configure the DMA channels */
    mcuxClDma_Utils_configureSgiTransferWithHandshakes(session,
                                                      MCUXCLSGI_DRV_DATIN0_OFFSET,
                                                      MCUXCLBUFFER_GET(pIn),
                                                      pOutPtr);

    mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks(session,
                                                     remainingBlocks,
                                                     (remainingBlocks - 1u) /* for CBC, the last output block needs to be copied seperately after SGI is stopped */
                                                     );

    /* Enable interrupts for the completion of the input channel, and for errors.
       As the output channel finishes first, there is not need to additionally enable DONE interrupts for it.
    */
    mcuxClDma_Drv_enableErrorInterrupts(inputChannel);
    mcuxClDma_Drv_enableErrorInterrupts(outputChannel);
    mcuxClDma_Drv_enableChannelDoneInterrupts(inputChannel);

    /* Enable SGI AUTO mode CBC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_CBC));

    /* Start the operation - this will start the SGI-DMA interaction in the background, CPU is not blocked */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_startAutoModeWithHandshakes));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_startAutoModeWithHandshakes(sgiCtrl | MCUXCLSGI_DRV_CTRL_NO_UP | MCUXCLSGI_DRV_CTRL_AES_NO_KL, MCUXCLSGI_UTILS_OUTPUT_HANDSHAKE_ENABLE));

    status = MCUXCLCIPHER_STATUS_JOB_STARTED;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Cbc_NonBlocking_Dec, status);
}
