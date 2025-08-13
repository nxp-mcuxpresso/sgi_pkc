/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>

#include <mcuxClAes.h>
#include <mcuxClBuffer.h>
#include <mcuxClCipherModes_MemoryConsumption.h>
#include <mcuxClKey.h>
#include <mcuxClMemory_Copy.h>
#include <mcuxClSession.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClCipher_Internal.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Cleanup.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>


#include <internal/mcuxClCrc_Internal_Functions.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_init_encrypt_Sgi, mcuxClCipher_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_init_encrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClKey_Handle_t pKey,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_init_encrypt_Sgi);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = mcuxClCipherModes_castToCipherModesAlgorithmAesSgi(pCtx->common.pMode->pAlgorithm);

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_checkIvLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->checkIvLength(session, ivLength));

  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClCipherModes_WorkArea_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  pWa->sgiWa.pKeyChecksums = &(pCtx->keyContext.keyChecksums);

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* SGI is successfully requested before this call, so it is ok to unconditionally call cleanup (with SGI) later on. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_init_internal_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_init_internal_Sgi(session, pWa, pCtx, pKey, pIv, ivLength));

  pCtx->setupIV = pAlgo->setupIVEncrypt;
  pCtx->protectionToken_setupIV = pAlgo->protectionToken_setupIVEncrypt;
  pCtx->processEngine = pAlgo->encryptEngine;
  pCtx->protectionToken_processEngine = pAlgo->protectionToken_encryptEngine;
  pCtx->finishSkeleton = mcuxClCipherModes_finish_encrypt_Sgi;
  pCtx->protectionToken_finishSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_finish_encrypt_Sgi);
  pCtx->direction = MCUXCLSGI_DRV_CTRL_ENC;

  /* Init context CRC - SREQI_BCIPHER_3 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, MCUXCLCIPHER_AES_CONTEXT_SIZE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_init_encrypt_Sgi);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_init_decrypt_Sgi, mcuxClCipher_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_init_decrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClKey_Handle_t pKey,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_init_decrypt_Sgi);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = mcuxClCipherModes_castToCipherModesAlgorithmAesSgi(pCtx->common.pMode->pAlgorithm);

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_checkIvLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->checkIvLength(session, ivLength));

  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClCipherModes_WorkArea_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  pWa->sgiWa.pKeyChecksums = &(pCtx->keyContext.keyChecksums);

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* SGI is successfully requested before this call, so it is ok to unconditionally call cleanup (with SGI) later on. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_init_internal_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_init_internal_Sgi(session, pWa, pCtx, pKey, pIv, ivLength));

  pCtx->setupIV = pAlgo->setupIVDecrypt;
  pCtx->protectionToken_setupIV = pAlgo->protectionToken_setupIVDecrypt;
  pCtx->processEngine = pAlgo->decryptEngine;
  pCtx->protectionToken_processEngine = pAlgo->protectionToken_decryptEngine;
  pCtx->finishSkeleton = mcuxClCipherModes_finish_decrypt_Sgi;
  pCtx->protectionToken_finishSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_finish_decrypt_Sgi);
  pCtx->direction = MCUXCLSGI_DRV_CTRL_DEC;

  /* Init context CRC - SREQI_BCIPHER_3 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, MCUXCLCIPHER_AES_CONTEXT_SIZE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_init_decrypt_Sgi);
}

/**
 * @brief Function to fill and process block buffer if it is necesssary
 *
 *  Move data from inputBufer to blockBuffer if:
 *   1. blockBuffer is not empty. After that if blockBuffer is full and there is remaining data in inputBuffer, process blockBuffer.
 *   2. inputBuffer has too little data to fill entire block.
 *
 * @param      session      Handle for the current CL session.
 * @param[in]  pContext     Pointer to multipart context
 * @param      pWa          Handle for the workarea
 * @param[in]  pKeyChecksum Pointer to mcuxClKey_KeyChecksum_t
 * @param[in]  pIn          Pointer to the input buffer
 * @param[out] pOut         Pointer to the output buffer
 * @param[in]  inLength     Length of the input buffer
 * @param[out] pInOffset    Offset of the @p pIn buffer
 * @param[out] pOutOffset   Offset of the @p pOut buffer
 * @param[out] pOutLength   Pointer to write/update the amount of written output bytes
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_fillAndProcessBlockBuffer)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_fillAndProcessBlockBuffer(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClKey_KeyChecksum_t* pKeyChecksum,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t * pInOffset,
  uint32_t * pOutOffset,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_fillAndProcessBlockBuffer);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);

  /* Move data from inputBuffer to blockBuffer if:
   *   1. blockBuffer is not empty
   *   2. inputBuffer has too little data to fill an entire block
   */
  if(0u != pCtx->common.blockBufferUsed || (MCUXCLAES_BLOCK_SIZE >= (inLength + pCtx->common.blockBufferUsed)))
  {
    /* Store bytes in context */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pCtx->common.blockBufferUsed, 0u, MCUXCLAES_BLOCK_SIZE, MCUXCLCIPHER_STATUS_FAULT_ATTACK)
    uint32_t bytesToCopy = MCUXCLCORE_MIN(MCUXCLAES_BLOCK_SIZE - pCtx->common.blockBufferUsed, inLength);

    MCUX_CSSL_DI_RECORD(bufferRead_smallInput_Process, (uint32_t)(pIn));
    MCUX_CSSL_DI_RECORD(bufferRead_smallInput_Process, (uint32_t)(&((uint8_t *)pCtx->blockBuffer)[pCtx->common.blockBufferUsed]));
    MCUX_CSSL_DI_RECORD(bufferRead_smallInput_Process, bytesToCopy);
    /* Non-secure read is sufficient to handle input. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(
      pIn,
      0u,
      &((uint8_t *)pCtx->blockBuffer)[pCtx->common.blockBufferUsed],
      bytesToCopy));

    *pInOffset = bytesToCopy;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("It can't wrap since blockBufferUsed and bytesTocopy are smaller than or equal to MCUXCLAES_BLOCK_SIZE.")
    pCtx->common.blockBufferUsed += bytesToCopy;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    /* If the blockBuffer is full and there is still data remaining in the inputBuffer, process this block. */
    if((MCUXCLAES_BLOCK_SIZE == pCtx->common.blockBufferUsed)
        && (inLength > bytesToCopy))
    {
      MCUXCLBUFFER_INIT(blockBuf, session, pCtx->blockBuffer, MCUXCLAES_BLOCK_SIZE);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_crypt));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_crypt(
        session,
        pCtx,
        pWa,
        blockBuf,
        pOut,
        MCUXCLAES_BLOCK_SIZE,
        pWa->pIV,
        pOutLength,
        pKeyChecksum,
        pCtx->processEngine,
        pCtx->protectionToken_processEngine));

      *pOutOffset = MCUXCLAES_BLOCK_SIZE;
      pCtx->common.blockBufferUsed = 0u;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_fillAndProcessBlockBuffer);
}

/**
 * @brief Function to handle remaining input
 *
 * This function processes full blocks of remaining bytes and
 * save the last block to pCtx->blockBuffer.
 *
 * @param      session        Handle for the current CL session.
 * @param[in]  pContext       Pointer to multipart context
 * @param      pWa            Handle for the workarea
 * @param[in]  pIn            Pointer to the input buffer
 * @param[out] pOut           Pointer to the output buffer
 * @param[in]  pKeyChecksum   Pointer to mcuxClKey_KeyChecksum_t
 * @param[out] pOutLength     Pointer to write/update the amount of written output bytes
 * @param[in]  remainingBytes Number of remaining bytes to process. Must be greater than 0.

 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_handleRemainingInput)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleRemainingInput(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  mcuxClKey_KeyChecksum_t* pKeyChecksum,
  uint32_t * const pOutLength,
  uint32_t remainingBytes)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_handleRemainingInput);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = mcuxClCipherModes_castToCipherModesAlgorithmAesSgi(pCtx->common.pMode->pAlgorithm);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(remainingBytes, 1u, UINT32_MAX, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  uint32_t lastBlockRemainingBytes = 0u;
  if((((1U == pAlgo->granularityEnc) && (MCUXCLSGI_DRV_CTRL_ENC == pCtx->direction))
    || ((1U == pAlgo->granularityDec) && (MCUXCLSGI_DRV_CTRL_DEC == pCtx->direction))))
  {
    /* In case of encryption / stream ciphers we can process all full blocks immediately. */
    lastBlockRemainingBytes = remainingBytes % MCUXCLAES_BLOCK_SIZE;
  }
  else
  {
    /* Process remaining full blocks (excluding last block!) from input buffer */
    lastBlockRemainingBytes = (remainingBytes - 1u) % MCUXCLAES_BLOCK_SIZE + 1u;  /* "lazy" processing */
  }

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(lastBlockRemainingBytes, 0u, remainingBytes, MCUXCLCIPHER_STATUS_INVALID_INPUT)
  uint32_t fullBlocksRemainingBytes = remainingBytes - lastBlockRemainingBytes;

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_crypt));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_crypt(
    session,
    pCtx,
    pWa,
    pIn,
    pOut,
    fullBlocksRemainingBytes,
    pWa->pIV,
    pOutLength,
    pKeyChecksum,
    pCtx->processEngine,
    pCtx->protectionToken_processEngine));

  if(NULL != pWa->pIV)
  {
    // Update IV in the context - IV is located in pWa->pIV which points to SGI data register
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int((uint8_t*)pCtx->ivState, (const uint8_t*)pWa->pIV, MCUXCLAES_BLOCK_SIZE));
  }

  /* Store remaining bytes which might form up to a full block in context */
  MCUXCLBUFFER_UPDATE(pIn, fullBlocksRemainingBytes);
  MCUX_CSSL_DI_RECORD(bufferRead_Process, (uint32_t)(pIn));
  MCUX_CSSL_DI_RECORD(bufferRead_Process, (uint32_t)(&((uint8_t *)pCtx->blockBuffer)[0u]));
  MCUX_CSSL_DI_RECORD(bufferRead_Process, lastBlockRemainingBytes);
  /* Non-secure read is sufficient to handle input. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(
    pIn,
    0u,
    &((uint8_t *)pCtx->blockBuffer)[0u],
    lastBlockRemainingBytes));

  pCtx->common.blockBufferUsed = lastBlockRemainingBytes;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_handleRemainingInput);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_process_Sgi, mcuxClCipher_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_process_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_process_Sgi);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);

  /* Validate the input size is in a meaningful range to also cover the bytes from the context */
  if(pCtx->common.totalInputLength > (UINT32_MAX - inLength))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
  }

  /* Check context CRC - SREQI_BCIPHER_3 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pContext, MCUXCLCIPHER_AES_CONTEXT_SIZE));

  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClCipherModes_WorkArea_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  mcuxClKey_KeyChecksum_t* pKeyChecksum = NULL;

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_loadMaskedKeyAndIvtoSgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_loadMaskedKeyAndIvtoSgi(
    session,
    (mcuxClCipherModes_Context_Aes_Sgi_t *) pCtx,
    pWa,
    inLength,
    &pKeyChecksum));

  uint32_t remainingBytes = inLength;
  uint32_t inOffset = 0u;
  uint32_t outOffset = 0u;

  MCUXCLBUFFER_DERIVE_RO(pInCur, pIn, inOffset);
  MCUXCLBUFFER_DERIVE_RW(pOutCur, pOut, outOffset);

  /* Move data from inputBufer to blockBuffer if:
   *   1. blockBuffer is not empty. After that if blockBuffer is full and there is remaining data in inputBuffer, process blockBuffer.
   *   2. inputBuffer has too little data to fill entire block.
   */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_fillAndProcessBlockBuffer));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_fillAndProcessBlockBuffer(
    session,
    pContext,
    pWa,
    pKeyChecksum,
    pInCur,
    pOutCur,
    inLength,
    &inOffset,
    &outOffset,
    pOutLength));

  MCUXCLBUFFER_UPDATE(pInCur, inOffset);
  MCUXCLBUFFER_UPDATE(pOutCur, outOffset);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inOffset, 0u, remainingBytes, MCUXCLCIPHER_STATUS_FAULT_ATTACK)
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("We have at least one block of data to process, therefore remainingBytes is greater than inOffset")
  remainingBytes -= inOffset;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  if (remainingBytes > 0u)
  {
    /* Balance the call to mcuxClMemory_copy_words_int for the copy of the IV to the context in the call to mcuxClCipherModes_handleRemainingInput.
     * Recording here already is fine, the pWa->pIV pointer will not be changed anymore after calling pCtx->setupIV. */
    if(NULL != pWa->pIV)
    {
      MCUX_CSSL_DI_RECORD(copyOfIv, (uint32_t) pCtx->ivState + (uint32_t) pWa->pIV + MCUXCLAES_BLOCK_SIZE);
    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_handleRemainingInput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_handleRemainingInput(
      session,
      pContext,
      pWa,
      pInCur,
      pOutCur,
      pKeyChecksum,
      pOutLength,
      remainingBytes));
  }

  /* Update total number of bytes that were encrypted */
  pCtx->common.totalInputLength += inLength;

  /* Update context CRC - SREQI_BCIPHER_3 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, MCUXCLCIPHER_AES_CONTEXT_SIZE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_process_Sgi, MCUXCLCIPHER_STATUS_OK);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_finish_Sgi, mcuxClCipher_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_finish_Sgi);

  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);
  MCUX_CSSL_DI_RECORD(cipherModesFinish_clearCtxOk, (uint8_t*)pCtx);
  MCUX_CSSL_DI_RECORD(cipherModesFinish_clearCtxOk, sizeof(mcuxClCipherModes_Context_Aes_Sgi_t));

  /* Check context CRC - SREQI_BCIPHER_3 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pContext, MCUXCLCIPHER_AES_CONTEXT_SIZE));

  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClCipherModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClCipherModes_WorkArea_t*, pWa, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

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
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->finishSkeleton(
    session,
    pWa,
    pContext,
    pOut,
    pOutLength));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));

  /* Invalidate context - SREQI_BCIPHER_15 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t*)pCtx, sizeof(mcuxClCipherModes_Context_Aes_Sgi_t)));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_finish_Sgi);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_init_internal_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_init_internal_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxClCipherModes_Context_Aes_Sgi_t * const pCtx,
  mcuxClKey_Handle_t pKey,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_init_internal_Sgi);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  pCtx->common.blockBufferUsed = 0u;
  /* Total number of bytes that were encrypted is initialized with zero */
  pCtx->common.totalInputLength = 0u;

  if (0u != ivLength)
  {
    MCUX_CSSL_DI_RECORD(bufferRead_Init, (uint32_t)(pIv));
    MCUX_CSSL_DI_RECORD(bufferRead_Init, (uint32_t)(pCtx->ivState));
    MCUX_CSSL_DI_RECORD(bufferRead_Init, ivLength);
    /* Non-secure read is sufficient to handle IV. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(
      pIv,
      0u,
      (uint8_t *)pCtx->ivState,
      ivLength));
  }

  /* Load key to SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, pKey, &pWa->sgiWa, MCUXCLSGI_DRV_KEY0_OFFSET));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_storeMaskedKeyInCtx_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_storeMaskedKeyInCtx_Sgi(
    session,
    pKey,
    &(pCtx->keyContext),
    &pWa->sgiWa,
    MCUXCLSGI_DRV_KEY0_OFFSET,
    mcuxClKey_getSize(pKey)
  ));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_init_internal_Sgi);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_finish_encrypt_Sgi, mcuxClCipherModes_FinishFunc_AesSgi_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_encrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_finish_encrypt_Sgi);

  mcuxClCipherModes_Context_Aes_Sgi_t * const pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = mcuxClCipherModes_castToCipherModesAlgorithmAesSgi(pCtx->common.pMode->pAlgorithm);
  mcuxClKey_KeyChecksum_t* pKeyChecksum = &pCtx->keyContext.keyChecksums;

  /* Return INVALID_INPUT if totalInputLength doesn't meet the required granularity */
  if(0u != (pCtx->common.totalInputLength % pAlgo->granularityEnc))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
  }

  uint32_t outputBytesWritten = 0u;

  /* If there is already full block in buffer, process it
   * (this can happen as process always pushes the last block of input into context, whether it is full or not) */
  if(MCUXCLAES_BLOCK_SIZE == pCtx->common.blockBufferUsed)
  {
    MCUXCLBUFFER_INIT_RO(ivBuff, session, pCtx->ivState, MCUXCLAES_BLOCK_SIZE_IN_WORDS);
    MCUX_CSSL_FP_EXPECT(pCtx->protectionToken_setupIV);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->setupIV(session, pWa, ivBuff));

    MCUXCLBUFFER_INIT(blockBuf, session, pCtx->blockBuffer, MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_crypt));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_crypt(
      session,
      pCtx,
      pWa,
      blockBuf,
      pOut,
      MCUXCLAES_BLOCK_SIZE,
      pWa->pIV,
      &outputBytesWritten,
      pKeyChecksum,
      pAlgo->encryptEngine,
      pAlgo->protectionToken_encryptEngine));

    pCtx->common.blockBufferUsed = 0u;
  }

  /* The SGI AUTO-mode might still be running if no input was processed so far
   * (can be the case, e.g., for CTR-NonBlocking mode, as it is started during the
   * pAlgo->setupIV step for this mode). We need to stop AUTO-mode here to bring the
   * SGI in non-busy state, because the PRNG (during certain padding modes) uses the SGI.
   * If AUTO-mode is not running anymore, stopping it will do no harm. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopAndDisableAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopAndDisableAutoMode());

  /* Check if padding needs to be applied, and if yes store the padded last block in the padding buffer */
  uint32_t paddingOutputSize = 0u;

  /* Create padding input buffer for input to addPadding function */
  MCUXCLBUFFER_INIT_RO(paddingInputBuffer, session, pCtx->blockBuffer, pCtx->common.blockBufferUsed);

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_addPadding);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->addPadding(
    session,
    MCUXCLAES_BLOCK_SIZE,
    paddingInputBuffer,
    0u,
    pCtx->common.blockBufferUsed,
    pCtx->common.totalInputLength,
    pWa->sgiWa.paddingBuff,
    &paddingOutputSize));

  if(0u == outputBytesWritten)
  {
    /* if engine was not yet called, setup the IV */
    MCUXCLBUFFER_INIT_RO(ivBuff, session, pCtx->ivState, MCUXCLAES_BLOCK_SIZE_IN_WORDS);
    MCUX_CSSL_FP_EXPECT(pCtx->protectionToken_setupIV);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->setupIV(session, pWa, ivBuff));
  }

  MCUXCLBUFFER_INIT(paddingBuf, session, pWa->sgiWa.paddingBuff, paddingOutputSize);
  MCUXCLBUFFER_DERIVE_RW(pOutBuf, pOut, 0u);
  /* Move input and output pointers */
  MCUXCLBUFFER_UPDATE(pOutBuf, outputBytesWritten);
  /* Process last (padded) block and store the result in the padding buffer */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_crypt));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_crypt(
    session,
    pCtx,
    pWa,
    paddingBuf,
    pOutBuf,
    paddingOutputSize,
    NULL,
    &outputBytesWritten,
    pKeyChecksum,
    pAlgo->encryptEngine,
    pAlgo->protectionToken_encryptEngine));

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("outputBytesWritten does not cause overflow as it depends on blockBufferUsed verified at the function entry")
  /* Update the output length and clean-up the session */
  *pOutLength += outputBytesWritten;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_finish_encrypt_Sgi);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_finish_decrypt_Sgi, mcuxClCipherModes_FinishFunc_AesSgi_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_finish_decrypt_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_finish_decrypt_Sgi);

  mcuxClCipherModes_Context_Aes_Sgi_t * const pCtx = mcuxClCipherModes_castToCipherModesContextAesSgi(pContext);
  mcuxClCipherModes_Algorithm_Aes_Sgi_t pAlgo = mcuxClCipherModes_castToCipherModesAlgorithmAesSgi(pCtx->common.pMode->pAlgorithm);
  mcuxClKey_KeyChecksum_t* pKeyChecksum = &pCtx->keyContext.keyChecksums;

  /* Return INVALID_INPUT if totalInputLength is zero for block cipher decryption or doesn't meet the required granularity */
  if(((0u == pCtx->common.totalInputLength) && (1u != pAlgo->granularityDec)) || (0u != (pCtx->common.totalInputLength % pAlgo->granularityDec)))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
  }

  /* Check that input granularity is correct for this mode, and add padding to incomplete last block (in case of stream cipher only).
     Note that the blockBuffer will contain the last block even if it is full. */
  /* if engine was not yet called, setup the IV */
  MCUXCLBUFFER_INIT_RO(ivBuff, session, pCtx->ivState, MCUXCLAES_BLOCK_SIZE_IN_WORDS);
  MCUX_CSSL_FP_EXPECT(pCtx->protectionToken_setupIV);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->setupIV(session, pWa, ivBuff));

  uint32_t outputBytesWritten = 0u;
  MCUXCLBUFFER_INIT(blockBuf, session, pCtx->blockBuffer, pCtx->common.blockBufferUsed);
  MCUXCLBUFFER_INIT_RW(paddingBuf, session, pWa->sgiWa.paddingBuff, pCtx->common.blockBufferUsed);
  /* Process the last (padded) block and store the result in the padding buffer */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_crypt));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCipherModes_crypt(
    session,
    pCtx,
    pWa,
    blockBuf,
    paddingBuf,
    pCtx->common.blockBufferUsed,
    NULL,
    &outputBytesWritten,
    pKeyChecksum,
    pAlgo->decryptEngine,
    pAlgo->protectionToken_decryptEngine));

  uint32_t paddingOutputSize = 0u;
  /* Remove the padding and copy the decrypted data of the last block to the output buffer */
  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_removePadding);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->removePadding(
    session,
    MCUXCLAES_BLOCK_SIZE,
    pWa->sgiWa.paddingBuff,
    pCtx->common.blockBufferUsed,
    pOut,
    0u,
    &paddingOutputSize));

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("paddingOutputSize does not cause overflow as it depends on blockBufferUsed verified at the function entry")
  /* Update the output length and clean-up the session */
  *pOutLength += paddingOutputSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_finish_decrypt_Sgi);
}
