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

#include <mcuxClCore_Macros.h>

#include <mcuxClAes.h>
#include <mcuxClBuffer.h>
#include <mcuxClCipherModes_MemoryConsumption.h>
#include <mcuxClKey.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>

#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClCipher_Internal.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Cleanup.h>
#include <internal/mcuxClCipherModes_Sgi_Functions.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Resource.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>

#include <internal/mcuxClCrc_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_encrypt_Sgi_dmaDriven, mcuxClCipher_CryptFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_encrypt_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t pKey,
  mcuxClCipher_Mode_t mode,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_encrypt_Sgi_dmaDriven);

  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = (mcuxClCipherModes_Algorithm_Aes_Sgi_t) mode->pAlgorithm;

  /* Return INVALID_INPUT if inLength doesn't meet the required granularity */
  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_checkIvLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->checkIvLength(session, ivLength));

  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClCipherModes_WorkArea_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  mcuxClKey_KeyChecksum_t keyChecksums;
  pWa->sgiWa.pKeyChecksums = &keyChecksums;

  /* Request the DMA channels and register callback function */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_requestDmaChannelsAndConfigureJobContext));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_requestDmaChannelsAndConfigureJobContext(
    session, pWa, mcuxClCipherModes_ISR_completeNonBlocking_oneshot,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_ISR_completeNonBlocking_oneshot)));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_NON_INTERRUPTABLE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key to SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, pKey, &pWa->sgiWa, MCUXCLSGI_DRV_KEY0_OFFSET));

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_setupIVEncrypt);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->setupIVEncrypt(session, pWa, pIv)); /* Load IV if needed, do nothing otherwise */

  uint32_t outputBytesWritten = 0u;

  uint32_t inOffset = 0u;
  uint32_t outOffset = 0u;

  /* Process all full blocks */
  if(MCUXCLAES_BLOCK_SIZE <= inLength)
  {
    /* Update workarea with information for callback function */
    pWa->nonBlockingWa.totalInputLength = inLength;
    pWa->nonBlockingWa.pOutputLength = pOutLength;
    pWa->nonBlockingWa.pAlgo = (const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t *) pAlgo;
    pWa->nonBlockingWa.direction = MCUXCLCIPHERMODES_ENCRYPT;
    pWa->nonBlockingWa.pOut = pOut;
    pWa->nonBlockingWa.outOffset = 0u;
    pWa->nonBlockingWa.pIn = pIn;
    pWa->nonBlockingWa.inOffset = 0u;

    MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_encryptEngine);
    MCUX_CSSL_FP_FUNCTION_CALL(encStatus, pAlgo->encryptEngine(
      session,
      pWa,
      pIn,
      pOut,
      inLength,
      pWa->pIV,
      &outputBytesWritten));

    if(MCUXCLCIPHER_STATUS_JOB_STARTED == encStatus)
    {
      /* Early exit for non-blocking, without clean-ups */
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_encrypt_Sgi_dmaDriven, encStatus);
    }

    /* Move input and output pointers, increase output length */
    inOffset += outputBytesWritten;
    outOffset += outputBytesWritten;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("outputBytesWritten has an upper bound of inLength")
    *pOutLength += outputBytesWritten;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
  }

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleLastBlock_enc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleLastBlock_enc(
    session,
    pWa,
    pAlgo,
    pIn,
    inOffset,
    inLength,
    pOut,
    outOffset,
    pOutLength));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven(session, NULL, pKey, cpuWaSizeInWords, MCUXCLCIPHERMODES_CLEANUP_HW_ALL));
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_encrypt_Sgi_dmaDriven, MCUXCLCIPHER_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_decrypt_Sgi_dmaDriven, mcuxClCipher_CryptFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_decrypt_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t pKey,
  mcuxClCipher_Mode_t mode,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_decrypt_Sgi_dmaDriven);

  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = (mcuxClCipherModes_Algorithm_Aes_Sgi_t) mode->pAlgorithm;

  /* Return INVALID_INPUT if inLength is zero for block cipher decryption or doesn't meet the required granularity */
  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_checkIvLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->checkIvLength(session, ivLength));
  if(((0u == inLength) && (1u != pAlgo->granularityDec)) ||
      (0u != inLength % pAlgo->granularityDec))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
  }

  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClCipherModes_WorkArea_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  mcuxClKey_KeyChecksum_t keyChecksums;
  pWa->sgiWa.pKeyChecksums = &keyChecksums;

  /* Request the DMA channels and register callback function */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_requestDmaChannelsAndConfigureJobContext));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_requestDmaChannelsAndConfigureJobContext(
    session, pWa, mcuxClCipherModes_ISR_completeNonBlocking_oneshot,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_ISR_completeNonBlocking_oneshot)));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_NON_INTERRUPTABLE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key to SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, pKey, &pWa->sgiWa, MCUXCLSGI_DRV_KEY0_OFFSET));

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_setupIVDecrypt);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->setupIVDecrypt(session, pWa, pIv)); /* Load IV if needed, do nothing otherwise */

  uint32_t inOffset = 0u;
  uint32_t outOffset = 0u;
  uint32_t outputBytesWritten = 0u;

  uint32_t size;
  if((1u == pAlgo->granularityDec) || (NULL == pAlgo->removePadding))
  {
    /* In the case of stream ciphers or when padding is set to "none", all full blocks can be processed immediately */
    /* TODO CLNS-14107 : update decryptEngine to handle all blocks at once for CTR*/
    size = (inLength / MCUXCLAES_BLOCK_SIZE) * MCUXCLAES_BLOCK_SIZE;
  }
  else
  {
    /* Round down to block size, if the last block is full it will not be considered here to be able to remove the padding later. */
    size = (inLength - 1u) & ~(MCUXCLAES_BLOCK_SIZE - 1u);
  }

  /* Process the considered full blocks */
  if(size > 0u)
  {
    /* Update workarea with information for callback function */
    pWa->nonBlockingWa.totalInputLength = inLength;
    pWa->nonBlockingWa.pOutputLength = pOutLength;
    pWa->nonBlockingWa.pAlgo = (const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t *) pAlgo;
    pWa->nonBlockingWa.direction = MCUXCLCIPHERMODES_DECRYPT;
    pWa->nonBlockingWa.pOut = pOut;
    pWa->nonBlockingWa.outOffset = 0u;
    pWa->nonBlockingWa.pIn = pIn;
    pWa->nonBlockingWa.inOffset = 0u;

    MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_decryptEngine);
    MCUX_CSSL_FP_FUNCTION_CALL(status, pAlgo->decryptEngine(
      session,
      pWa,
      pIn,
      pOut,
      size,
      pWa->pIV,
      &outputBytesWritten));

    if(MCUXCLCIPHER_STATUS_JOB_STARTED == status)
    {
      /* Early exit for non-blocking, without clean-ups */
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_decrypt_Sgi_dmaDriven, status);
    }

    /* Move input and output pointers, increase output length */
    inOffset += outputBytesWritten;
    outOffset += outputBytesWritten;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("*pOutLength was initialized to 0 by all callers, and the total additions to *pOutLength have an upper bound of inLength.")
    *pOutLength += outputBytesWritten;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
  }

  /* For no padding, all data are already processed. */
  if(NULL != pAlgo->removePadding)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleLastBlock_dec));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleLastBlock_dec(session, pWa, pAlgo, pIn, inOffset, inLength, pOut, outOffset, pOutLength));
  }

  /* STATUS_OK is protected */
  MCUX_CSSL_DI_RECORD(cipherDecryptRetCode, MCUXCLCIPHER_STATUS_OK);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven(
    session, NULL, NULL /* TODO CLNS-16946: store keys in nonBlocking WA and flush it here */,
    cpuWaSizeInWords, MCUXCLCIPHERMODES_CLEANUP_HW_ALL));
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_decrypt_Sgi_dmaDriven, MCUXCLCIPHER_STATUS_OK);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_ISR_completeNonBlocking_oneshot, mcuxClSession_HwInterruptHandler_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_ISR_completeNonBlocking_oneshot(
  mcuxClSession_Handle_t session
)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_ISR_completeNonBlocking_oneshot);
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  /* Wait for both channels, to be sure */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForHandshakeChannelsDone));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForHandshakeChannelsDone(session));

  /* SGI needs a manual stop once all data is processed (or on DMA channel error). Disable interrupts. */
  // TODO CLNS-17266: consider properly stopping the AUTO-mode an cleaning-up DMA channels in a public cleanUp API, see handling below
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes(inputChannel, outputChannel));

  mcuxClDma_Drv_disableChannelDoneInterrupts(inputChannel);
  mcuxClDma_Drv_disableChannelDoneInterrupts(outputChannel);
  mcuxClDma_Drv_disableErrorInterrupts(inputChannel);
  mcuxClDma_Drv_disableErrorInterrupts(outputChannel);

  /* Determine cpu workarea size */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));

  /*
   * AUTO mode finished as expected.
   * Continue with the operation - wrap-up AUTO mode and handle the last block
   */

  mcuxClCipherModes_WorkArea_t * pWa = (mcuxClCipherModes_WorkArea_t *) mcuxClSession_job_getClWorkarea(session) ;
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = (mcuxClCipherModes_Algorithm_Aes_Sgi_t) pWa->nonBlockingWa.pAlgo;

  /* Increase output length and pointer with bytes written by AUTO mode */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_readMajorBeginningLoopCount));
  MCUX_CSSL_FP_FUNCTION_CALL(uint16_t, blockWrittenWithDma, mcuxClDma_Drv_readMajorBeginningLoopCount(outputChannel));
  uint32_t bytesWritten = (uint32_t) blockWrittenWithDma * MCUXCLAES_BLOCK_SIZE;
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_readMajorBeginningLoopCount));
  MCUX_CSSL_FP_FUNCTION_CALL(uint16_t, blockReadWithDma, mcuxClDma_Drv_readMajorBeginningLoopCount(inputChannel));
  uint32_t bytesRead = (uint32_t) blockReadWithDma * MCUXCLAES_BLOCK_SIZE;

  /* Advance pointers and output size */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Total outOffset/inOffset and *pOutputLength have an upper bound of inLength")
  pWa->nonBlockingWa.inOffset += bytesRead;
  pWa->nonBlockingWa.outOffset += bytesWritten;
  *pWa->nonBlockingWa.pOutputLength += bytesWritten;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_completeAutoModeEngine);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->completeAutoModeEngine(session, mcuxClSession_job_getClWorkarea(session)));

  /* Handle the last block as always */
  if(MCUXCLCIPHERMODES_ENCRYPT == pWa->nonBlockingWa.direction)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleLastBlock_enc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleLastBlock_enc(session, pWa, pAlgo,
                                                  pWa->nonBlockingWa.pIn, pWa->nonBlockingWa.inOffset, pWa->nonBlockingWa.totalInputLength,
                                                  pWa->nonBlockingWa.pOut, pWa->nonBlockingWa.outOffset, pWa->nonBlockingWa.pOutputLength));
  }
  else /* MCUXCLCIPHERMODES_DECRYPT == pWa->nonBlockingWa.direction */
  {
    /* For no padding, all data are already processed. */
    if(NULL != pAlgo->removePadding)
    {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleLastBlock_dec));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleLastBlock_dec(session, pWa, pAlgo,
                                                  pWa->nonBlockingWa.pIn, pWa->nonBlockingWa.inOffset, pWa->nonBlockingWa.totalInputLength,
                                                  pWa->nonBlockingWa.pOut, pWa->nonBlockingWa.outOffset, pWa->nonBlockingWa.pOutputLength));
    }
  }

  /* Notify the user that the operation finished */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven(session, NULL, NULL /* TODO CLNS-16946: store keys in nonBlocking WA and flush it here */, cpuWaSizeInWords, MCUXCLCIPHERMODES_CLEANUP_HW_ALL));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_triggerUserCallback));
  MCUX_CSSL_FP_FUNCTION_CALL(retSessionTriggerCallback, mcuxClSession_triggerUserCallback(session, MCUXCLCIPHER_STATUS_JOB_COMPLETED));
  if(MCUXCLSESSION_STATUS_OK != retSessionTriggerCallback)
  {
    MCUXCLSESSION_ERROR(session, retSessionTriggerCallback);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_ISR_completeNonBlocking_oneshot);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_handleLastBlock_enc)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleLastBlock_enc(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t totalInputLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_handleLastBlock_enc);

  uint32_t lastBlockLength = totalInputLength % MCUXCLAES_BLOCK_SIZE;

  /* Check if padding needs to be applied, and if yes store the padded last block in the padding buffer */
  uint32_t paddingOutputSize = 0u;

  /* The SGI AUTO-mode might still be running if no input was processed so far
   * (can be the case, e.g., for CTR-NonBlocking mode, as it is started during the
   * pAlgo->setupIV step for this mode). We need to stop AUTO-mode here to bring the
   * SGI in non-busy state, because the PRNG (during certain padding modes) uses the SGI.
   * If AUTO-mode is not running anymore, stopping it will do no harm. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopAndDisableAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopAndDisableAutoMode());

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_addPadding);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->addPadding(
    session,
    MCUXCLAES_BLOCK_SIZE,
    pIn,
    inOffset,
    lastBlockLength,
    totalInputLength,
    pWa->sgiWa.paddingBuff,
    &paddingOutputSize));

  if(0u == paddingOutputSize)
  {
    /* Nothing to do - exit */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_handleLastBlock_enc);
  }

  uint32_t outputBytesWritten = 0u;
  /* Move input and output pointers */
  MCUXCLBUFFER_DERIVE_RW(pOutCur, pOut, outOffset);
  MCUXCLBUFFER_INIT(paddingBuf, session, pWa->sgiWa.paddingBuff, paddingOutputSize);
  /* Process last (padded) block and store the result in the padding buffer */
  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_encryptEngine);
  MCUX_CSSL_FP_FUNCTION_CALL(status, pAlgo->encryptEngine(
    session,
    pWa,
    paddingBuf,
    pOutCur,
    paddingOutputSize,
    NULL,
    &outputBytesWritten));
  (void) status; /* One-block processing is blocking -  encryptEngine only returns OK */

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("*pOutLength has an upper bound of totalInputLength")
  *pOutLength += outputBytesWritten;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_handleLastBlock_enc);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_handleLastBlock_dec)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleLastBlock_dec(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t totalInputLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_handleLastBlock_dec);

  uint32_t lastBlockLength;

  if((pAlgo->granularityDec == 1u))
  {
    /* In case of stream ciphers or no padding, all full blocks have already been processed. Handle remaining bytes. */
    lastBlockLength = totalInputLength % MCUXCLAES_BLOCK_SIZE;
  }
  else
  {
    /* For modes with the need for padding removal, a full block might still be left to process. */
    lastBlockLength = (0u == totalInputLength) ? 0u : (((totalInputLength + (MCUXCLAES_BLOCK_SIZE - 1u)) % MCUXCLAES_BLOCK_SIZE) +  1u);
  }


  if(0u == lastBlockLength)
  {
    /* Nothing to do - exit */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_handleLastBlock_dec);
  }

  uint32_t outputBytesWritten = 0u;
  /* Move input and output pointers */
  MCUXCLBUFFER_DERIVE_RO(pInCur, pIn, inOffset);
  MCUXCLBUFFER_INIT_RW(ptempBuf, session, pWa->sgiWa.paddingBuff, lastBlockLength);

  /* Process the last block and store the result in the padding buffer */
  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_decryptEngine);
  MCUX_CSSL_FP_FUNCTION_CALL(status, pAlgo->decryptEngine(
    session,
    pWa,
    pInCur,
    ptempBuf,
    lastBlockLength,
    NULL,
    &outputBytesWritten));
  (void) status; /* One-block processing is blocking -  decryptEngine only returns OK */

  uint32_t paddingOutputSize = 0u;
  /* Remove the padding and copy the decrypted last block to the output buffer */
  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_removePadding);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->removePadding(
    session,
    MCUXCLAES_BLOCK_SIZE,
    pWa->sgiWa.paddingBuff,
    lastBlockLength,
    pOut,
    outOffset,
    &paddingOutputSize));

  /* Update the output length */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("paddingOutputSize does not cause overflow as it depends on inLength verified in higher level caller")
  *pOutLength += paddingOutputSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_OVERFLOWED_TRUNCATED_STATUS_CODE()
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_handleLastBlock_dec);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OVERFLOWED_TRUNCATED_STATUS_CODE()
}
