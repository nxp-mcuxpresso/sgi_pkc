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

#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

#include <internal/mcuxClResource_Internal_Types.h>

#include <internal/mcuxClCrc_Internal_Functions.h>

#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Resource.h>

#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>

#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_Macros.h>

#include <mcuxClAes.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCipherModes_MemoryConsumption.h>

#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClCipher_Internal.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Functions.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <internal/mcuxClCipherModes_Sgi_Cleanup.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>

/**
 * @brief Function to handle OK and ERROR/FAILURE exit
 *
 * Use this function to leave functions in this file in _not_ FAULT_ATTACK cases.
 * It frees CPU workarea, releases the DMA and uninitializes the SGI.
 *
 * @param      session          Handle for the current CL session.
 * @param      pContext         Pointer to multipart context
 * @param      key              Handle for the used key
 * @param[in]  cpuWaSizeInWords Number of cpu wa words to free
 * @param[in]  cleanupDmaSgi    Instructions on whether to clean DMA, SGI,
 *                               can be either of these values:
 *                                 #MCUXCLCIPHERMODES_CLEANUP_HW_ALL
 *                                 #MCUXCLCIPHERMODES_CLEANUP_HW_SGI
 *                                 #MCUXCLCIPHERMODES_CLEANUP_HW_DMA
 *                                 #MCUXCLCIPHERMODES_CLEANUP_HW_NONE
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_cleanupOnExit_dmaDriven)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_cleanupOnExit_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_Context_Aes_Sgi_t *pContext,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords,
  uint32_t cleanupDmaSgi)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_cleanupOnExit_dmaDriven);

  /* Free CPU WA in Session */
  mcuxClSession_freeWords_cpuWa(session, cpuWaSizeInWords);

  if(0u != (cleanupDmaSgi & MCUXCLCIPHERMODES_CLEANUP_HW_DMA))
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_releaseInputAndOutput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_releaseInputAndOutput(session));
  }

  if(0u != (cleanupDmaSgi & MCUXCLCIPHERMODES_CLEANUP_HW_SGI))
  {
    /* Flush the given key, if needed */
    if((NULL != key)
        && (MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED != (mcuxClKey_getLoadStatus(key) & MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED))
      )
    {
      /* Flush the key in use if it is not preloaded.
      * Note that we purposefully don't flush the whole SGI or the whole Key bank to not overwrite other keys. */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush_internal));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_flush_internal(session, key, 0U /* spec */));
    }
    else if(NULL != pContext)
    {
      /* Flush the key in the context, if needed */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_flushKeyInContext));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_flushKeyInContext(session, &(pContext->keyContext)));
    }
    else
    {
      /* intentionally empty */
    }


    /* Uninitialize (and release) the SGI hardware */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Uninit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Uninit(session));
  }

  if (NULL != pContext)
  {
    /* Update context CRC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(&pContext->common, MCUXCLCIPHER_AES_CONTEXT_SIZE));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven);
}

/**
 * @brief Function to handle DMA errors that occurred during SGI AUTO mode with handshakes.
 *
 * This function cleans up the AUTO mode.
 *
 * @return void
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_handleDmaError_autoModeNonBlocking)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleDmaError_autoModeNonBlocking(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_handleDmaError_autoModeNonBlocking);

  /* Perform a dummy SGI_DATOUT read to be sure AUTO mode is wrapped-up correctly */
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 0u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 4u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 8u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 12u);

  /* Known bug in SGI AUTO mode: if AUTO_MODE.CMD is not reset to 0 , subsequent SGI operations will not work.
     Workaround: wait for SGI and reset AUTO_MODE to 0. To be removed in CLNS-7392 once fixed in HW. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());
  mcuxClSgi_Drv_resetAutoMode();

  /* Channels do not need to be canceled / stopped. Minor loop will just not be triggered again with handshakes disabled. */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_handleDmaError_autoModeNonBlocking);
}


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
  mcuxClCipherModes_WorkArea_t *pWa = mcuxClCipherModes_castToCipherModesWorkArea(mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  mcuxClKey_KeyChecksum_t keyChecksums;
  pWa->sgiWa.pKeyChecksums = &keyChecksums;

  /* Request the DMA channels and register callback function */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_requestDmaInputAndOutputWithWorkarea));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(MCUXCLCIPHERMODES_REQUEST_DMA_CHANNELS(
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
  mcuxClCipherModes_WorkArea_t *pWa = mcuxClCipherModes_castToCipherModesWorkArea(mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  mcuxClKey_KeyChecksum_t keyChecksums;
  pWa->sgiWa.pKeyChecksums = &keyChecksums;

  /* Request the DMA channels and register callback function */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_requestDmaInputAndOutputWithWorkarea));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(MCUXCLCIPHERMODES_REQUEST_DMA_CHANNELS(
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
  if((pAlgo->granularityDec == 1u))
  {
    /* in case of stream ciphers all full blocks can be processed immediately. */
    /* TODO CLNS-14107 : update decryptEngine to handle all blocks at once for CTR*/
    size = (inLength / MCUXCLAES_BLOCK_SIZE) * MCUXCLAES_BLOCK_SIZE;
  }
  else
  {
    /* Round down to block size, if the last block is full it will not be considered here */
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
    *pOutLength += outputBytesWritten;
  }

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleLastBlock_dec));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleLastBlock_dec(
    session,
    pWa,
    pAlgo,
    pIn,
    inOffset,
    inLength,
    pOut,
    outOffset,
    pOutLength));

  /* STATUS_OK is protected */
  MCUX_CSSL_DI_RECORD(cipherDecryptRetCode, MCUXCLCIPHER_STATUS_OK);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven(session, NULL, NULL /* TODO CLNS-16946: store keys in nonBlocking WA and flush it here */, cpuWaSizeInWords, MCUXCLCIPHERMODES_CLEANUP_HW_ALL));
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
  uint32_t bytesWritten = ((uint32_t)mcuxClDma_Drv_readMajorBeginningLoopCount(outputChannel)) * MCUXCLAES_BLOCK_SIZE;
  uint32_t bytesRead = ((uint32_t)mcuxClDma_Drv_readMajorBeginningLoopCount(inputChannel)) * MCUXCLAES_BLOCK_SIZE;

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
  else if (MCUXCLCIPHERMODES_DECRYPT == pWa->nonBlockingWa.direction)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleLastBlock_dec));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleLastBlock_dec(session, pWa, pAlgo,
                                                  pWa->nonBlockingWa.pIn, pWa->nonBlockingWa.inOffset, pWa->nonBlockingWa.totalInputLength,
                                                  pWa->nonBlockingWa.pOut, pWa->nonBlockingWa.outOffset, pWa->nonBlockingWa.pOutputLength));
  }
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLCIPHER_STATUS_FAULT_ATTACK);
  }

  /* Notify the user that the operation finished */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven(session, NULL, NULL /* TODO CLNS-16946: store keys in nonBlocking WA and flush it here */, cpuWaSizeInWords, MCUXCLCIPHERMODES_CLEANUP_HW_ALL));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_triggerUserCallback));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSession_triggerUserCallback(session, MCUXCLCIPHER_STATUS_JOB_COMPLETED));

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
    /* in case of stream ciphers all full blocks have already been processed. */
    lastBlockLength = totalInputLength % MCUXCLAES_BLOCK_SIZE;
  }
  else
  {
    /* all but the final block have already been processed. */
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



/**
 * @brief Function to fill and process block buffer if it is necesssary
 *
 *  Move data from inputBufer to blockBuffer if:
 *   1. blockBuffer is not empty. After that if blockBuffer is full and there is remaining data in inputBuffer, process blockBuffer.
 *   2. inputBuffer has too little data to fill entire block.
 *
 * @param      session    Handle for the current CL session.
 * @param[in]  pContext   Pointer to multipart context
 * @param      pWa        Handle for the workarea
 * @param[in]  pIn        Pointer to the input buffer
 * @param[out] pOut       Pointer to the output buffer
 * @param[in]  inLength   Length of the input buffer
 * @param[out] pInOffset  Offset of the @p pIn buffer
 * @param[out] pOutOffset Offset of the @p pOut buffer
 * @param[out] pOutLength Pointer to write/update the amount of written output bytes
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_fillAndProcessBlockBuffer_dmaDriven)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_fillAndProcessBlockBuffer_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t * pInOffset,
  uint32_t * pOutOffset,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_fillAndProcessBlockBuffer_dmaDriven);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);

  /* Move data from inputBuffer to blockBuffer if:
   *   1. blockBuffer is not empty
   *   2. inputBuffer has too little data to fill an entire block
   */
  if(0u != pCtx->common.blockBufferUsed || (MCUXCLAES_BLOCK_SIZE  >= (inLength + pCtx->common.blockBufferUsed)))
  {
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pCtx->common.blockBufferUsed, 0u, MCUXCLAES_BLOCK_SIZE, MCUXCLCIPHER_STATUS_FAULT_ATTACK)
    /* Store bytes in context */
    uint32_t bytesToCopy = MCUXCLCORE_MIN(MCUXCLAES_BLOCK_SIZE - pCtx->common.blockBufferUsed, inLength);

    MCUX_CSSL_DI_RECORD(bufferRead_smallInput_ProcessDmaDriven, (uint32_t)(pIn) + *pInOffset);
    MCUX_CSSL_DI_RECORD(bufferRead_smallInput_ProcessDmaDriven, (uint32_t)(&((uint8_t *)pCtx->blockBuffer)[pCtx->common.blockBufferUsed]) + bytesToCopy);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(
      pIn,
      *pInOffset,
      &((uint8_t *)pCtx->blockBuffer)[pCtx->common.blockBufferUsed],
      bytesToCopy));

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("pInOffset + bytesToCopy is always smaller than UINT32_MAX")
    *pInOffset += bytesToCopy;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("It can't wrap since blockBufferUsed and bytesTocopy are smaller than or equal to MCUXCLAES_BLOCK_SIZE.")
    pCtx->common.blockBufferUsed += bytesToCopy;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    /* If the blockBuffer is full and there is still data remaining in the inputBuffer, process this block. */
    if((MCUXCLAES_BLOCK_SIZE == pCtx->common.blockBufferUsed)
        && (inLength > bytesToCopy))
    {
      MCUXCLBUFFER_INIT(blockBuff, session, pCtx->blockBuffer, MCUXCLAES_BLOCK_SIZE);
      MCUX_CSSL_FP_EXPECT(pCtx->protectionToken_processEngine);
      MCUX_CSSL_FP_FUNCTION_CALL(status, pCtx->processEngine(
        session,
        pWa,
        blockBuff,
        pOut,
        MCUXCLAES_BLOCK_SIZE,
        pWa->pIV,
        pOutLength));
      (void) status; /* One-block processing is blocking -  processEngine only returns OK */

      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("pOutOffset cannot overflow as it is always initialized to 0, and is guaranteed to be increased by at max the 32-bit input size.")
      *pOutOffset += MCUXCLAES_BLOCK_SIZE;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

      pCtx->common.blockBufferUsed = 0u;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_fillAndProcessBlockBuffer_dmaDriven);
}

/**
 * @brief Function to handle remaining input
 *
 * This function processes full blocks of remaining bytes and
 * calls mcuxClCipherModes_handleLastBlock_process for the last block.
 *
 * @param      session        Handle for the current CL session.
 * @param[in]  pContext       Pointer to multipart context
 * @param      pWa            Handle for the workarea
 * @param[in]  pIn            Pointer to the input buffer
 * @param[out] pOut           Pointer to the output buffer
 * @param[out] pOutLength     Pointer to write/update the amount of written output bytes
 * @param[in]  remainingBytes Number of remaining bytes to process
 * @param[in]  inOffset       Offset of the @p pIn buffer
 * @param[in]  outOffset      Offset of the @p pOut buffer

 *
 * @return mcuxClCipher_Status_t
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_handleRemainingInput_dmaDriven)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_handleRemainingInput_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength,
  uint32_t remainingBytes,
  uint32_t inOffset,
  uint32_t outOffset)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_handleRemainingInput_dmaDriven);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = (mcuxClCipherModes_Algorithm_Aes_Sgi_t) pCtx->common.pMode->pAlgorithm;

  uint32_t lastBlockRemainingBytes = 0u;
  if((((pAlgo->granularityEnc == 1u) && (pCtx->direction == MCUXCLSGI_DRV_CTRL_ENC))
    || ((pAlgo->granularityDec == 1u) && (pCtx->direction == MCUXCLSGI_DRV_CTRL_DEC))))
  {
    /* In case of encryption / stream ciphers we can process all full blocks immediately. */
    lastBlockRemainingBytes = remainingBytes % MCUXCLAES_BLOCK_SIZE;
  }
  else
  {
    /* Process remaining full blocks (excluding last block!) from input buffer */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("remainingBytes can't be less than 1u")
    lastBlockRemainingBytes = (remainingBytes - 1u) % MCUXCLAES_BLOCK_SIZE + 1u; /* "lazy" processing */
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
  }

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(lastBlockRemainingBytes, 0u, remainingBytes, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  uint32_t fullBlocksRemainingBytes = remainingBytes - lastBlockRemainingBytes;

  /* Update workarea with information for callback function */
  pWa->nonBlockingWa.pAlgo = (const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t *) pAlgo;
  pWa->nonBlockingWa.pContext = pCtx;
  pWa->nonBlockingWa.lastBlockRemainingBytes = lastBlockRemainingBytes;
  pWa->nonBlockingWa.pOutputLength = pOutLength;
  pWa->nonBlockingWa.pOut = pOut;
  pWa->nonBlockingWa.outOffset = outOffset;
  pWa->nonBlockingWa.pIn = pIn;
  pWa->nonBlockingWa.inOffset = inOffset;
  if((uint32_t) pAlgo->decryptEngine == (uint32_t) pCtx->processEngine)
  {
    pWa->nonBlockingWa.direction = MCUXCLCIPHERMODES_DECRYPT;
  }
  else
  {
    pWa->nonBlockingWa.direction = MCUXCLCIPHERMODES_ENCRYPT;
  }

  if (0u != fullBlocksRemainingBytes)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("inOffset has an upper bound of inLength")
    MCUXCLBUFFER_DERIVE_RO(pInCur, pIn, inOffset);
    MCUXCLBUFFER_DERIVE_RW(pOutCur, pOut, outOffset);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_EXPECT(pCtx->protectionToken_processEngine);
    MCUX_CSSL_FP_FUNCTION_CALL(status, pCtx->processEngine(
      session,
      pWa,
      pInCur,
      pOutCur,
      fullBlocksRemainingBytes,
      pWa->pIV,
      pOutLength));

    if(MCUXCLCIPHER_STATUS_JOB_STARTED == status)
    {
      /* Early exit for non-blocking, without clean-ups */
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_OVERFLOWED_TRUNCATED_STATUS_CODE()
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_handleRemainingInput_dmaDriven, status);
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OVERFLOWED_TRUNCATED_STATUS_CODE()
    }

      /* Update input offset after call to processEngine */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(fullBlocksRemainingBytes, 0u, UINT32_MAX - inOffset, MCUXCLCIPHER_STATUS_FAULT_ATTACK)
    inOffset += fullBlocksRemainingBytes;
  }

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("inOffset has an upper bound of inLength")
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleLastBlock_process));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleLastBlock_process(
    session,
    pWa,
    pCtx,
    pAlgo,
    pIn,
    inOffset,
    lastBlockRemainingBytes));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_handleRemainingInput_dmaDriven, MCUXCLCIPHER_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_process_Sgi_dmaDriven, mcuxClCipher_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_process_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_process_Sgi_dmaDriven);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);

  /* Check context CRC */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pContext, MCUXCLCIPHER_AES_CONTEXT_SIZE));

  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  mcuxClCipherModes_WorkArea_t *pWa = mcuxClCipherModes_castToCipherModesWorkArea(mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Request the DMA channels and register callback function */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_requestDmaInputAndOutputWithWorkarea));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(MCUXCLCIPHERMODES_REQUEST_DMA_CHANNELS(
    session, pWa, mcuxClCipherModes_ISR_completeNonBlocking_multipart,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_ISR_completeNonBlocking_multipart)));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_NON_INTERRUPTABLE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Update total number of bytes that were sent to process */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("pCtx->common.totalInputLength has an upper bound of inLength")
  pCtx->common.totalInputLength += inLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_loadMaskedKeyAndIvtoSgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_loadMaskedKeyAndIvtoSgi(
    session,
    (mcuxClCipherModes_Context_Aes_Sgi_t *) pCtx,
    pWa,
    inLength,
    NULL));

  uint32_t remainingBytes = inLength;
  uint32_t inOffset = 0u;
  uint32_t outOffset = 0u;

  /* Move data from inputBufer to blockBuffer if:
   *   1. blockBuffer is not empty. After that if blockBuffer is full and there is remaining data in inputBuffer, process blockBuffer.
   *   2. inputBuffer has too little data to fill entire block.
   */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_fillAndProcessBlockBuffer_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_fillAndProcessBlockBuffer_dmaDriven(
    session,
    pContext,
    pWa,
    pIn,
    pOut,
    inLength,
    &inOffset,
    &outOffset,
    pOutLength));

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inOffset, 0u, remainingBytes, MCUXCLCIPHER_STATUS_FAULT_ATTACK)
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("We have at least one block of data to process, therefore remainingBytes is greater than inOffset")
  remainingBytes -= inOffset;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  if (remainingBytes > 0u)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleRemainingInput_dmaDriven));
    MCUX_CSSL_FP_FUNCTION_CALL(handleStatus, mcuxClCipherModes_handleRemainingInput_dmaDriven(
      session,
      pContext,
      pWa,
      pIn,
      pOut,
      pOutLength,
      remainingBytes,
      inOffset,
      outOffset));

    if (MCUXCLCIPHER_STATUS_JOB_STARTED == handleStatus)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_process_Sgi_dmaDriven, handleStatus);
    }
  }

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords, MCUXCLCIPHERMODES_CLEANUP_HW_ALL));
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_process_Sgi_dmaDriven, MCUXCLCIPHER_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_finish_Sgi_dmaDriven, mcuxClCipher_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_Sgi_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_finish_Sgi_dmaDriven);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);
  MCUX_CSSL_DI_RECORD(cipherModesFinishDma_clearCtxOk, (uint8_t*)pCtx);
  MCUX_CSSL_DI_RECORD(cipherModesFinishDma_clearCtxOk, sizeof(mcuxClCipherModes_Context_Aes_Sgi_t));

  /* Check context CRC - SREQI_BCIPHER_3 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pContext, MCUXCLCIPHER_AES_CONTEXT_SIZE));

  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  mcuxClCipherModes_WorkArea_t *pWa = mcuxClCipherModes_castToCipherModesWorkArea(mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Request the DMA channels and register callback function */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_requestDmaInputAndOutputWithWorkarea));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(MCUXCLCIPHERMODES_REQUEST_DMA_CHANNELS(session, pWa, NULL, 0U));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session,
                                                                   &(pCtx->keyContext),
                                                                   &pWa->sgiWa,
                                                                   MCUXCLSGI_DRV_KEY0_OFFSET,
                                                                   MCUXCLAES_MASKED_KEY_SIZE));

  MCUX_CSSL_FP_EXPECT(pCtx->protectionToken_finishSkeleton);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->finishSkeleton(session, pWa, pContext, pOut, pOutLength));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords, MCUXCLCIPHERMODES_CLEANUP_HW_ALL));

  /* Invalidate context - SREQI_BCIPHER_15 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t*)pCtx, sizeof(mcuxClCipherModes_Context_Aes_Sgi_t)));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_finish_Sgi_dmaDriven);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_ISR_completeNonBlocking_multipart, mcuxClSession_HwInterruptHandler_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_ISR_completeNonBlocking_multipart(
  mcuxClSession_Handle_t session
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_ISR_completeNonBlocking_multipart);

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  /* Wait for both channels, to be sure */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForHandshakeChannelsDone));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForHandshakeChannelsDone(session));

  /* SGI needs a manual stop once all data is processed (or on DMA channel error). Disable interrupts. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes(inputChannel, outputChannel));

  mcuxClDma_Drv_disableChannelDoneInterrupts(inputChannel);
  mcuxClDma_Drv_disableChannelDoneInterrupts(outputChannel);
  mcuxClDma_Drv_disableErrorInterrupts(inputChannel);
  mcuxClDma_Drv_disableErrorInterrupts(outputChannel);

  /* Determine cpu workarea size and workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  mcuxClCipherModes_WorkArea_t * pWa = (mcuxClCipherModes_WorkArea_t *) mcuxClSession_job_getClWorkarea(session);
  /* Read multipart context from workarea */
  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = pWa->nonBlockingWa.pContext;

  /*
   * AUTO mode finished as expected.
   * Continue with the operation - wrap-up AUTO mode and handle the remaining bytes
   */

  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = (mcuxClCipherModes_Algorithm_Aes_Sgi_t) pWa->nonBlockingWa.pAlgo;

  uint32_t lastBlockRemainingBytes = pWa->nonBlockingWa.lastBlockRemainingBytes;

  /* Increase output length and pointer with bytes written by AUTO mode */
  uint32_t bytesWritten = ((uint32_t)mcuxClDma_Drv_readMajorBeginningLoopCount(outputChannel)) * MCUXCLAES_BLOCK_SIZE;
  uint32_t bytesRead = ((uint32_t)mcuxClDma_Drv_readMajorBeginningLoopCount(inputChannel)) * MCUXCLAES_BLOCK_SIZE;

  /* Advance pointers and output size */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Total outOffset/inOffset and *pOutputLength have an upper bound of inLength")
  pWa->nonBlockingWa.inOffset += bytesRead;
  pWa->nonBlockingWa.outOffset += bytesWritten;
  *pWa->nonBlockingWa.pOutputLength += bytesWritten;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_completeAutoModeEngine);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->completeAutoModeEngine(session, mcuxClSession_job_getClWorkarea(session)));

  /* Update ctx for further process calls */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleLastBlock_process));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleLastBlock_process(
    session,
    pWa,
    pCtx,
    pAlgo,
    pWa->nonBlockingWa.pIn, pWa->nonBlockingWa.inOffset,
    lastBlockRemainingBytes));

  /* Notify the user that the operation finished */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit_dmaDriven));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit_dmaDriven(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords, MCUXCLCIPHERMODES_CLEANUP_HW_ALL));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_triggerUserCallback));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSession_triggerUserCallback(session, MCUXCLCIPHER_STATUS_JOB_COMPLETED));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_ISR_completeNonBlocking_multipart);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_handleLastBlock_process)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleLastBlock_process(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClCipherModes_Context_Aes_Sgi_t *pCtx,
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo UNUSED_PARAM,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockRemainingBytes
)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_handleLastBlock_process);

  if(NULL != pWa->pIV)
  {
    //Update IV - IV is located in pIV which points to SGI data register
    MCUX_CSSL_DI_RECORD(copyIvToContext, (uint32_t)pCtx->ivState);
    MCUX_CSSL_DI_RECORD(copyIvToContext, (uint32_t)pWa->pIV + MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int((uint8_t*)pCtx->ivState, (const uint8_t*)pWa->pIV, MCUXCLAES_BLOCK_SIZE));
  }

  /* Store remaining bytes, which might form up to a full block, in context */
  MCUX_CSSL_DI_RECORD(bufferRead_handleLastBlockProcess, (uint32_t)(pIn) + inOffset);
  MCUX_CSSL_DI_RECORD(bufferRead_handleLastBlockProcess, (uint32_t)(pCtx->blockBuffer) + lastBlockRemainingBytes);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, inOffset, pCtx->blockBuffer, lastBlockRemainingBytes));
  pCtx->common.blockBufferUsed = lastBlockRemainingBytes;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_handleLastBlock_process);
}
