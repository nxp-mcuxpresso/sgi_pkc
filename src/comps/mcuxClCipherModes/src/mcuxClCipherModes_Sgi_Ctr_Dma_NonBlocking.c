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
#include <internal/mcuxClMemory_Copy_Internal.h>

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_Ctr_NonBlocking, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ctr_NonBlocking(mcuxClSession_Handle_t session, mcuxClCipherModes_WorkArea_t* pWa, mcuxCl_InputBuffer_t pIn, mcuxCl_Buffer_t pOut,
                                                          uint32_t inLength, uint32_t* pIvOut, uint32_t* const pOutLength);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_Ctr_NonBlocking_CompleteAutoMode, mcuxClCipherModes_completeAutoModeFunc_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_Ctr_NonBlocking_CompleteAutoMode(mcuxClSession_Handle_t session, mcuxClCipherModes_WorkArea_t* pWa);

/**
 * @brief The descriptor for the AES CTR mode with DMA access (non-blocking).
 */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CTR_Sgi_NonBlocking =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  .encryptEngine                                 = mcuxClCipherModes_Ctr_NonBlocking,
  .protectionToken_encryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ctr_NonBlocking),
  .decryptEngine                                 = mcuxClCipherModes_Ctr_NonBlocking,
  .protectionToken_decryptEngine                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ctr_NonBlocking),
  .completeAutoModeEngine                        = mcuxClCipherModes_Ctr_NonBlocking_CompleteAutoMode,
  .protectionToken_completeAutoModeEngine        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_Ctr_NonBlocking_CompleteAutoMode),
  .setupIVEncrypt                                = mcuxClCipherModes_IV_AutoMode_Ctr,
  .protectionToken_setupIVEncrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_AutoMode_Ctr),
  .setupIVDecrypt                                = mcuxClCipherModes_IV_AutoMode_Ctr,
  .protectionToken_setupIVDecrypt                = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_IV_AutoMode_Ctr),
  .checkIvLength                                 = mcuxClCipherModes_checkIvLen,
  .protectionToken_checkIvLength                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_checkIvLen),
  .addPadding                                    = mcuxClPadding_addPadding_Stream,
  .protectionToken_addPadding                    = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_Stream),
  .removePadding                                 = mcuxClPadding_removePadding_Stream,
  .protectionToken_removePadding                 = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_Stream),
  .granularityEnc                                = 1u,
  .granularityDec                                = 1u
};

/**
 * @brief This function is called by the DMA interrupt after the automode for AES CTR mode is finished.
 *        It increases the IV/counter value of the backup counter in DATAIN2 to the current value.
 *
 * @param[in]     session         The handle of the current session
 * @param[in]     pWa             A pointer to the current work area (unused)
 *
 * @return void
 *
 * @pre    The SGI automode is finished.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ctr_NonBlocking_CompleteAutoMode, mcuxClCipherModes_completeAutoModeFunc_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_Ctr_NonBlocking_CompleteAutoMode(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClCipherModes_WorkArea_t* pWa UNUSED_PARAM
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ctr_NonBlocking_CompleteAutoMode);

  /* Known bug in SGI AUTO mode: if AUTO_MODE.CMD is not reset to 0 here, subsequent SGI operations will not work.
     Workaround: After final result was read, wait for SGI and reset AUTO_MODE to 0. To be removed in CLNS-7392 once fixed in HW. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait()); /* Known limitation: wait for SGI busy flag to be de-asserted before overwriting AUTO mode CMD */
  mcuxClSgi_Drv_resetAutoMode();

  /* The IV in DATIN0 is always incremented "too early" in AUTO-mode. For this reason, decrement DATIN0 by 1u and store it in DATIN2. Then, use DATIN2 when processing the remaining input in normal mode. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_decrement128Bit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_decrement128Bit(MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLSGI_DRV_DATIN2_OFFSET));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_Ctr_NonBlocking_CompleteAutoMode);
}

 /**
  * @brief This function is the encrypt/ decrypt engine for AES in CTR mode with DMA (non-blocking).
  *        When at least two full blocks are passed to the function, it starts the SGI automode.
  *        Otherwise, the function disables the automode, copies one block to the SGI, waits for encryption/ decryption
  *        to finish, increases the IV/counter and copies the block from the SGI.
  *
  * @param[in]    session         The handle of the current session
  * @param[in]    pWa             A pointer to the current work area
  * @param[in]    pIn             The input buffer with the data to encrypt/ decrypt
  * @param[out]   pOut            The output buffer to which the encryption/ decryption of the input buffer is written to
  * @param[in]    inLength        The length of the input buffer
  * @param[out]   pIvOut          This pointer is used to copy the IV/ CTR from DATAIN0 in the single block case
  * @param[out]   pOutLength      This pointer is used to write the length of the output buffer
  * @return       A status code indicating if the function was successful
  *
  * @pre
  *   - The key is in SGI key register KEY0
  *   - The counter is in DATAIN0 and DATAIN2
  *   - If inLength >= 2 * AES_BLOCK_SIZE: The SGI already started in automode
  * @post
  *   - if inLength >= 2 * AES_BLOCK_SIZE: SGI automode started and running
  */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_Ctr_NonBlocking, mcuxClCipherModes_EngineFunc_AesSgi_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_Ctr_NonBlocking(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut,
  uint32_t* const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_Ctr_NonBlocking);

  if(inLength > MCUXCLDMA_UTILS_SGI_AUTOMODE_MAX_INPUT_SIZE)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
  }

  uint32_t remainingBlocks = inLength /  MCUXCLAES_BLOCK_SIZE;
  uint32_t lastBlockLength = (0u == remainingBlocks) ? (inLength % MCUXCLAES_BLOCK_SIZE) : MCUXCLAES_BLOCK_SIZE;
  if((0u == remainingBlocks) && (0u == lastBlockLength))
  {
    /* Nothing to do - exit */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Ctr_NonBlocking, MCUXCLCIPHER_STATUS_OK);
  }

  uint8_t *pOutPtr = (uint8_t *) MCUXCLBUFFER_GET(pOut);
  uint8_t *pPaddingPtr = pWa->sgiWa.paddingBuff;
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  uint32_t sgiCtrl = MCUXCLSGI_DRV_CTRL_ENC           |
                     pWa->sgiWa.sgiCtrlKey;

  mcuxClCipher_Status_t status;
  if(remainingBlocks <= 1u)
  {
    /* For only one block of data, SGI AUTO-mode is not needed. */

    /* Stop and disable AUTO mode, as it was started/enabled during setupIV */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopAndDisableAutoMode));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopAndDisableAutoMode());
    /* Known bug in SGI AUTO mode: if AUTO_MODE.CMD is not reset to 0 here, subsequent SGI operations will not work.
       Workaround: Reset AUTO_MODE to 0. To be removed in CLNS-7392 once fixed in HW. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait()); /* Known limitation: wait for SGI busy flag to be de-asserted before overwriting AUTO mode CMD */
    mcuxClSgi_Drv_resetAutoMode();

    /* The IV in DATIN0 is always incremented "too early" in AUTO-mode. For this reason, decrement DATIN0 by 1u and store it in DATIN2. Then, use DATIN2 when processing in normal mode. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_decrement128Bit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_decrement128Bit(MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLSGI_DRV_DATIN2_OFFSET));

    if((inLength < MCUXCLAES_BLOCK_SIZE)  && (pWa->sgiWa.paddingBuff != MCUXCLBUFFER_GET(pIn)))
    {
      MCUX_CSSL_DI_RECORD(sgiLoad, ((uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN1_OFFSET)) + (uint32_t)pIn + (uint32_t)inLength + (uint32_t)pWa->sgiWa.paddingBuff);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load_notFull128Block_buffer));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load_notFull128Block_buffer(MCUXCLSGI_DRV_DATIN1_OFFSET, pIn, inLength, pWa->sgiWa.paddingBuff));
    }
    else
    {
      /* Copy full block of input to SGI */
      mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN1_OFFSET, MCUXCLBUFFER_GET(pIn));
      mcuxClDma_Utils_startTransferOneBlock(inputChannel);

      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));
    }

    /* Perform encryption */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
      MCUXCLSGI_DRV_CTRL_END_UP                  |
      MCUXCLSGI_DRV_CTRL_INSEL_DATIN2            | /* IV stored in DATIN2 */
      MCUXCLSGI_DRV_CTRL_OUTSEL_RES_XOR_DATIN1   | /* XOR output with DATIN1 (input block) */
      sgiCtrl));

    /* Increase the counter value "manually" if AUTO mode is not used */
    MCUX_CSSL_DI_RECORD(incLength, MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_incrementData));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_incrementData(MCUXCLSGI_DRV_DATIN2_OFFSET, MCUXCLAES_BLOCK_SIZE));

    /* Copy output block from SGI */
    mcuxClDma_Utils_configureSgiOutputChannel(session, MCUXCLSGI_DRV_DATOUT_OFFSET, pPaddingPtr);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());
    mcuxClDma_Utils_startTransferOneBlock(outputChannel);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, outputChannel));

    MCUX_CSSL_DI_RECORD(mcuxClBuffer_write_params, pOut);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_write_params, pPaddingPtr);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_write_params, lastBlockLength);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(pOut, 0u, pPaddingPtr, lastBlockLength));

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("*pOutLength has an upper bound of inLength")
    *pOutLength += lastBlockLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    if(NULL != pIvOut)
    {
      /* Reconfigure the SGI to prepare for AUTO mode in the next call to the CTR engine.
         Not needed if pIvOut is NULL, as this indicates the last call to the engine. */

      /* Known limitation of CTR: Configure and start the SGI in AUTO mode CTR before loading the IV */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_CTR_128));
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(sgiCtrl | MCUXCLSGI_DRV_CTRL_NO_UP));

      /* Copy the updated IV to DATIN0.
         Note that DMA transfer is not needed here because this is not an I/O operation. */
      MCUXCLSGI_UTILS_LOAD128BITBLOCK_DI_BALANCED(MCUXCLSGI_DRV_DATIN0_OFFSET, (uint8_t *)pIvOut);
    }

    status = MCUXCLCIPHER_STATUS_OK;
  }
  else /* remainingBlocks > 1u */
  {
    /* For multiple blocks, use SGI AUTO mode with handshakes */

    /* Configure the DMA channels */
    mcuxClDma_Utils_configureSgiTransferWithHandshakes(session,
                                                      MCUXCLSGI_DRV_DATIN1_OFFSET,
                                                      MCUXCLBUFFER_GET(pIn),
                                                      pOutPtr);

    mcuxClDma_Utils_SgiHandshakes_writeNumberOfBlocks(session,
                                                     remainingBlocks,
                                                     remainingBlocks /* for CTR, all blocks can be read with the DMA handshake signals */
                                                     );

    /* Enable interrupts for the completion of the input channel, and for errors.
       As the output channel finishes first, there is not need to additionally enable DONE interrupts for it.
    */
    mcuxClDma_Drv_enableErrorInterrupts(inputChannel);
    mcuxClDma_Drv_enableErrorInterrupts(outputChannel);
    mcuxClDma_Drv_enableChannelDoneInterrupts(inputChannel);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableDmaHandshakes));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableDmaHandshakes());

    status = MCUXCLCIPHER_STATUS_JOB_STARTED;

    /* No need to reconfigure the SGI to prepare for AUTO mode in the next call to the CTR engine.
       There is no case where multiple-block processing is followed by another multiple-block processing without
       calling setupIV in between, which starts AUTO mode. */
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_Ctr_NonBlocking, status);
}
