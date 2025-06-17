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
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClResource_Internal_Types.h>
#include <internal/mcuxClResource_Internal_Functions.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClAes.h>
#include <internal/mcuxClDma_Drv.h>
#include <mcuxClDma_Types.h>
#include <internal/mcuxClDma_Utils_Sgi.h>
#include <internal/mcuxClDma_Resource.h>
#include <mcuxClBuffer.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClHashModes_Internal_Resource_Common.h>
#include <mcuxClCore_Macros.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

/**********************************************************
 * Helper functions
 **********************************************************/
/**
 * @brief Sha2 nonBlocking interrupt service routine cleanup and exit
 *
 * This routine is intended to be executed as last step of interrupt callback.
 * Session workare reserved memory space is freed, SGI flushed and released,
 * DMA released and user callback triggered
 *
 * @param session Current session handle
 * @param waWordSize Work area size in words to be freed
 * @param userCallbackStatus Return value to be forwared in user callback
 * @param releaseOption Option from MCUXCLHASHMODES_REQ_* define set indicating which
 *        hardware resource shall be released
 *
 * @pre
 *  - session job workarea must point to initialized interrupt context
 * (mcuxClSession_job_setClWorkarea with initialized structure with Internal IsrCtx type)
 *  - required hardware should be requested before routine execution:
 *    - Input Dma
 *    - SGI
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sha2Nonblocking_CleanupAndTriggerUserCallback)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_Sha2Nonblocking_CleanupAndTriggerUserCallback(
    mcuxClSession_Handle_t session,
    uint32_t waWordSize,
    mcuxClHash_Status_t userCallbackStatus,
    uint32_t releaseOption)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sha2Nonblocking_CleanupAndTriggerUserCallback);
    mcuxClSession_freeWords_cpuWa(session, waWordSize);

    /* flush whole SGI */
    // TODO CLNS-16291: FLUSH_KEY for SGI is not usable anymore with preloaded keys
    // mcuxClSgi_Drv_enableFlush(MCUXCLSGI_DRV_FLUSH_ALL);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRelease));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRelease(session, releaseOption));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_triggerUserCallback));
    MCUX_CSSL_FP_FUNCTION_CALL(ucStatus, mcuxClSession_triggerUserCallback(session, userCallbackStatus));
    if(MCUXCLSESSION_STATUS_OK != ucStatus)
    {
        MCUXCLSESSION_ERROR(session, ucStatus);
    }
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHashModes_Sha2Nonblocking_CleanupAndTriggerUserCallback);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_castToSha2OneshotInternalIsrCtx)
static mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t* mcuxClHashModes_castToSha2OneshotInternalIsrCtx(uint32_t* pContext)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t*) pContext;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_castToSha2MultipartInternalIsrCtx)
static mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t* mcuxClHashModes_castToSha2MultipartInternalIsrCtx(uint32_t* pContext)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t*) pContext;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

/**********************************************************
 * *INTERNAL* layer functions
 **********************************************************/

/**
 * @brief Sha2 Oneshot (Init/Update/Finalize) Interrupt Service Routine (ISR).
 *
 * This routine is intended to be executed as an interrupt callback after SGI
 * has finished processing. It will check if the Sha2 operation has finished
 * without any errors, process last block, copy out the result and trigger
 * user callback on exit. In case of one-shot compare, this function will
 * compare the result against the reference before triggering the user callback.
 *
 * @param session Current session handle
 *
 * @pre
 *  - session job workarea must point to initialized interrupt context
 * (mcuxClSession_job_setWa with initialized structure of mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t)
 *  - required hardware must be requested before routine execution:
 *    - Input Dma (input gathering)
 *    - SGI (sha2 calculation)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sha2Sgi_ISR_Oneshot, mcuxClSession_HwInterruptHandler_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_Sha2Sgi_ISR_Oneshot(mcuxClSession_Handle_t session)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sha2Sgi_ISR_Oneshot);

    mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t *isrCtx = mcuxClHashModes_castToSha2OneshotInternalIsrCtx(mcuxClSession_job_getClWorkarea(session));
    mcuxClSession_Channel_t inChannel = mcuxClSession_getDmaInputChannel(session);
    mcuxCl_InputBuffer_t inputBuf = isrCtx->inputBuf;

    uint32_t workareaSizeToFree = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t));
    mcuxClHash_AlgorithmDescriptor_t *algorithm = isrCtx->algorithm;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("the result is less than MAX of uint32_t as algorithm->hashSize is limited to MCUXCLHASH_MAX_OUTPUT_SIZE")
    const uint32_t outputBufferWordSize = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->hashSize);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storeHashResult_recordDI));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storeHashResult_recordDI(isrCtx->pOut, outputBufferWordSize));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_checkForChannelErrors));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_checkForChannelErrors(session, inChannel));

    /**************************************************************************************
     * Step 3: Pad the input data and process last block
     **************************************************************************************/
    uint32_t numberOfFullBlocks = isrCtx->numberOfFullBlocks;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Cannot wrap as algorithm->blockSize is limited to MCUXCLHASH_BLOCK_SIZE_MAX")
    uint32_t offset = numberOfFullBlocks * algorithm->blockSize;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    size_t inSize = isrCtx->inSize;

    /* Buffer in CPU WA to store the last block of data in the finalization phase */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Cannot wrap as algorithm->blockSize is limited to MCUXCLHASH_BLOCK_SIZE_MAX")
    uint32_t *shaBlock = mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    uint8_t *shaBlockBytes = (uint8_t *)shaBlock;

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Cannot wrap as algorithm->blockSize is limited to MCUXCLHASH_BLOCK_SIZE_MAX")
    workareaSizeToFree += MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("algorithm->blockSize is greater than 1 regarding to macro definition")
    size_t sizeRemainingBlock = inSize & (algorithm->blockSize - 1u);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    /* Balance DI impact of mcuxClBuffer_read. */
    MCUX_CSSL_DI_RECORD(bufferReadBalancing, inputBuf);
    MCUX_CSSL_DI_RECORD(bufferReadBalancing, offset);
    MCUX_CSSL_DI_RECORD(bufferReadBalancing, shaBlock);
    MCUX_CSSL_DI_RECORD(bufferReadBalancing, sizeRemainingBlock);
    /* Copy the data to the buffer in the workspace. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Offset computation does not overflow")
    // TODO CLNS-16738: Investigate whether we want Function call here? Needed to be reverted for FP build.
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(inputBuf, offset, shaBlockBytes, sizeRemainingBlock));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    /* add first byte of the padding: (remaining) < (block length) so there is space in the buffer */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("sizeRemainingBlock did not wrap, sizeRemainingBlock increased by 1 is less than MAX of uint32_t regarding to the initialization above")
    shaBlockBytes[sizeRemainingBlock] = 0x80u;
    sizeRemainingBlock += 1u;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    uint32_t numberOfZeroBytes = algorithm->blockSize - sizeRemainingBlock;

    /* Process partial padded block if needed */
    if (algorithm->counterSize > numberOfZeroBytes) // need room for 64 bit counter and one additional byte
    {
        MCUX_CSSL_DI_RECORD(setShablock1, &shaBlockBytes[sizeRemainingBlock]);
        MCUX_CSSL_DI_RECORD(setShablock1, numberOfZeroBytes);
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("shaBlockBytes + sizeRemainingBlock does not overflow");
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(&shaBlockBytes[sizeRemainingBlock], 0x00u, numberOfZeroBytes));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

        /* Load input data to SHA FIFO */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(shaBlock, algorithm->blockSize));
        sizeRemainingBlock = 0u;
        numberOfZeroBytes = algorithm->blockSize;
    }

    /* Perform padding by adding data counter */
    MCUX_CSSL_DI_RECORD(setShablock2, &shaBlockBytes[sizeRemainingBlock]);
    MCUX_CSSL_DI_RECORD(setShablock2, numberOfZeroBytes);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("shaBlockBytes + sizeRemainingBlock does not overflow")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(&shaBlockBytes[sizeRemainingBlock], 0x00u, numberOfZeroBytes));

    sizeRemainingBlock = algorithm->blockSize;
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize <<  3u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >>  5u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >> 13u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >> 21u) & 0xFFu);
    shaBlockBytes[sizeRemainingBlock - 1u] = (uint8_t)(inSize >> 29u);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    /* Load input data to SHA FIFO */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(shaBlock, algorithm->blockSize));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

    uint32_t expectedSgiCounter = ((numberOfZeroBytes == algorithm->blockSize) ? 1u : 0u);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("expectedSgiCounter is less than MAX of uint32_t")
    expectedSgiCounter += numberOfFullBlocks + 1u;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    /* Wait until SGI has finished */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    /* Check whether number of processed blocks is correct */
    expectedSgiCounter = expectedSgiCounter % (MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE + 1u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_checkHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_checkHashCounter(session, expectedSgiCounter));

    mcuxClHash_Status_t userCallbackStatus = MCUXCLHASH_STATUS_FAULT_ATTACK;

    /**************************************************************************************
    * Step 4: Copy result to output buffers
    **************************************************************************************/

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storeHashResult));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storeHashResult(session, isrCtx->pOut, algorithm->hashSize));

    *isrCtx->pOutSize = algorithm->hashSize;
    userCallbackStatus = MCUXCLHASH_STATUS_JOB_COMPLETED;


    /* Clean-up */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_close));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_close(session));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_Sha2Nonblocking_CleanupAndTriggerUserCallback));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_Sha2Nonblocking_CleanupAndTriggerUserCallback(
        session,
        workareaSizeToFree,
        userCallbackStatus,
        MCUXCLHASHMODES_REQ_SGI | MCUXCLHASHMODES_REQ_DMA_INPUT | MCUXCLHASHMODES_REQ_DMA_OUTPUT
    ));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHashModes_Sha2Sgi_ISR_Oneshot);
}

/**
 * @brief Sha2 Multipart Process (Update) Interrupt Service Routine (ISR).
 *
 * This routine is intended to be executed as an interrupt callback after SGI
 * has finished processing. It will check if the Sha2 operation has finished
 * without any errors, copy out the context and trigger
 * user callback on exit.
 *
 * @param session Current session handle
 *
 * @pre
 *  - session job workarea must point to initialized interrupt context
 * (mcuxClSession_job_setWa with initialized structure of mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t)
 *  - required hardware must be requested before routine execution:
 *    - Input Dma (input gathering)
 *    - SGI (sha2 calculation)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sha2Sgi_ISR_Multipart, mcuxClSession_HwInterruptHandler_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_Sha2Sgi_ISR_Multipart(mcuxClSession_Handle_t session)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sha2Sgi_ISR_Multipart);

    mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t *isrCtx = mcuxClHashModes_castToSha2MultipartInternalIsrCtx(mcuxClSession_job_getClWorkarea(session));
    mcuxClSession_Channel_t inChannel = mcuxClSession_getDmaInputChannel(session);
    mcuxCl_InputBuffer_t inputBuf = isrCtx->inputBuf;
    mcuxClHash_ContextDescriptor_t *context = isrCtx->ctx;
    uint8_t *pUnprocessed = (uint8_t *)mcuxClHash_getUnprocessedPtr(context);
    uint32_t *pState = mcuxClHash_getStatePtr(context);
    const mcuxClHash_AlgorithmDescriptor_t *algorithm = context->algo;

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_checkForChannelErrors));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_checkForChannelErrors(session, inChannel));

    uint32_t numberOfFullBlocks = isrCtx->numberOfFullBlocks;
    size_t inSize = isrCtx->inSize;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("the result is less than MAX of uint32_t as algorithm->blockSize is limited to PH_NCCLHASH_BLOCK_SIZE_MAX")
    size_t sizeRemainingBlock = inSize & (algorithm->blockSize - 1u);
    uint32_t offset = numberOfFullBlocks * algorithm->blockSize + isrCtx->inputOffset;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

    /* Wait until SGI has finished */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    uint32_t expectedSgiCounter = numberOfFullBlocks + (((isrCtx->inputOffset > 0u) && (0u == context->unprocessedLength))? 1u : 0u);
    /* Check whether number of processed blocks is correct */
    expectedSgiCounter = expectedSgiCounter % (MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE + 1u);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_checkHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_checkHashCounter(session, expectedSgiCounter));
    /* Reach here mean more than 1 block processed correctly with DMA, then need store the state for next process */
    /* Extract state from SGI and put it into context */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storePartialHash));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storePartialHash(pState, algorithm->stateSize));

    /* Copy the remaining data to the buffer in the workspace. */
    if (0u < sizeRemainingBlock)
    {
        /* Balance DI impact of mcuxClBuffer_read. */
        MCUX_CSSL_DI_RECORD(bufferReadBalancing, inputBuf);
        MCUX_CSSL_DI_RECORD(bufferReadBalancing, offset);
        MCUX_CSSL_DI_RECORD(bufferReadBalancing, pUnprocessed);
        MCUX_CSSL_DI_RECORD(bufferReadBalancing, sizeRemainingBlock);

        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Offset computation does not overflow")
        // TODO CLNS-16738: Investigate whether we want Function call here? Needed to be reverted for FP build.
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(inputBuf, offset, pUnprocessed, sizeRemainingBlock));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

        context->unprocessedLength = sizeRemainingBlock;
    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_Sha2Nonblocking_CleanupAndTriggerUserCallback));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_Sha2Nonblocking_CleanupAndTriggerUserCallback(
        session,
        MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t)),
        MCUXCLHASH_STATUS_JOB_COMPLETED,
        MCUXCLHASHMODES_REQ_SGI | MCUXCLHASHMODES_REQ_DMA_INPUT
    ));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHashModes_Sha2Sgi_ISR_Multipart);
}

/**
 * @brief Oneshot Skeleton core implementation for DMA non-blocking Sha2 with SGI support
 *
 * Data Integrity: Expunge(pIn + inSize + pOut + pOutSize)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking_Core)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking_Core (
                        mcuxClSession_Handle_t session,
                        mcuxClHash_Algo_t algorithm,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize,
                        mcuxCl_Buffer_t pOut,
                        uint32_t *const pOutSize
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking_Core);

    /**************************************************************************************
     * Step 1: Initialize SGI to perform Hash operation of dedicated algorithm
     **************************************************************************************/
    mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
    const mcuxClHashModes_Internal_AlgorithmDescriptor_t *algorithmDetails = (const mcuxClHashModes_Internal_AlgorithmDescriptor_t *) algorithm->pAlgorithmDetails;

    /* Error handled inside HwRequest */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRequest));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRequest(
      session,
      mcuxClHashModes_Sha2Sgi_ISR_Oneshot,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_Sha2Sgi_ISR_Oneshot),
      MCUXCLHASHMODES_REQ_SGI | MCUXCLHASHMODES_REQ_DMA_INPUT | MCUXCLHASHMODES_REQ_DMA_OUTPUT));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));

    /* Configure respective SHA-2 in auto mode using standard IV */
    MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiUtilsInitHash);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiUtilsInitHash(NULL, MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV));

    /* Enable counter, to count number of blocks processed by SGI */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableHashCounter(0u));

    /**************************************************************************************
     * Step 2: Process full blocks of input data
     **************************************************************************************/

    /* All blocks can be processed in bulk directly from in */
    uint32_t numberOfFullBlocks = inSize / algorithm->blockSize;

    /* Wait until SGI is ready to take input */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    /* Start SGI SHA2 processing */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

    if (0u < numberOfFullBlocks)
    {
        /* Load input data to FIFO register banks */
        /* Configure the DMA channels */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("numberOfFullBlocks * algorithm->blockSize cannot overflow")
        mcuxClDma_Utils_configureSgiSha2InputChannel(session,
                                                    MCUXCLBUFFER_GET(pIn),
                                                    numberOfFullBlocks * algorithm->blockSize);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

        /* Enable interrupts for the completion of the input channel and for errors */
        mcuxClDma_Drv_enableChannelDoneInterrupts(inputChannel);
        mcuxClDma_Drv_enableErrorInterrupts(inputChannel);

        mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t *isrCtx = mcuxClHashModes_castToSha2OneshotInternalIsrCtx(mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t))));

        isrCtx->inSize = inSize;
        isrCtx->inputBuf = pIn;
        isrCtx->numberOfFullBlocks = numberOfFullBlocks;
        isrCtx->pOut = pOut;
        isrCtx->pOutSize = pOutSize;
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST("Algorithm field cannot be const to be able to set it")
        isrCtx->algorithm = (mcuxClHash_AlgorithmDescriptor_t *)algorithm;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST()
        mcuxClSession_job_setClWorkarea(session, isrCtx);

        /* Enable the DMA */
        mcuxClDma_Drv_startChannel(inputChannel);

        MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, pIn);
        MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, inSize);
        MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, pOut);
        MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, pOutSize);

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking_Core, MCUXCLHASH_STATUS_JOB_STARTED);
    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storeHashResult_recordDI));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storeHashResult_recordDI(pOut, algorithm->hashSize));

    /**************************************************************************************
     * Step 3: Pad the input data and process last block
     **************************************************************************************/
    /* Buffer in CPU WA to store the last block of data in the finalization phase */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize) cannot wrap")
    uint32_t *shaBlock = mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    uint8_t *shaBlockBytes = (uint8_t *)shaBlock;

    /* Balance DI impact of mcuxClBuffer_read. */

    /* pIn and inSize are deliberately not recorded for bufferReadBalancing,
     * because mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking_Core is supposed to expunge pIn and inSize.
     */
    MCUX_CSSL_DI_RECORD(bufferReadBalancing, shaBlock);

    /* Copy the data to the buffer in the workspace. */
    /* Copy input to accumulation buffer */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
    /* Error handled inside buffer_read*/
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, 0u, shaBlockBytes, inSize));

    /* add first byte of the padding: (remaining) < (block length) so there is space in the buffer */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("the result does not wrap since inSize is less then a block")
    shaBlockBytes[inSize] = 0x80u;
    uint32_t sizeRemainingBlock = inSize + 1u;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    uint32_t numberOfZeroBytes = algorithm->blockSize - sizeRemainingBlock;

    /* Process partial padded block if needed */
    if (algorithm->counterSize > numberOfZeroBytes) // need room for 64 bit counter and one additional byte
    {
        MCUX_CSSL_DI_RECORD(setShablock1, &shaBlockBytes[sizeRemainingBlock]);
        MCUX_CSSL_DI_RECORD(setShablock1, numberOfZeroBytes);
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("shaBlockBytes + sizeRemainingBlock does not overflow")
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(&shaBlockBytes[sizeRemainingBlock], 0x00u, numberOfZeroBytes));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

        /* Load input data to SHA FIFO */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(shaBlock, algorithm->blockSize));
        sizeRemainingBlock = 0u;
        numberOfZeroBytes = algorithm->blockSize;
    }

    /* Perform padding by adding data counter */
    MCUX_CSSL_DI_RECORD(setShablock2, &shaBlockBytes[sizeRemainingBlock]);
    MCUX_CSSL_DI_RECORD(setShablock2, numberOfZeroBytes);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("shaBlockBytes + sizeRemainingBlock does not overflow")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(&shaBlockBytes[sizeRemainingBlock], 0x00u, numberOfZeroBytes));

    sizeRemainingBlock = algorithm->blockSize;
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize <<  3u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >>  5u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >> 13u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >> 21u) & 0xFFu);
    shaBlockBytes[sizeRemainingBlock - 1u] = (uint8_t)(inSize >> 29u);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    /* Load input data to SHA FIFO */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(shaBlock, algorithm->blockSize));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

    mcuxClSession_freeWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize));
    /**************************************************************************************
     * Step 4: Copy result to output buffers
     **************************************************************************************/
    uint32_t expectedSgiCounter = ((numberOfZeroBytes == algorithm->blockSize) ? 1u : 0u);
    expectedSgiCounter += numberOfFullBlocks + 1u;


    /* pIn and inSize already expunged by bufferReadBalancing. */
    MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, pOut);
    MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, pOutSize);

    /* Complete all operations */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_Sgi_Sha2End));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_Sgi_Sha2End(
      session,
      algorithm,
      expectedSgiCounter,
      pOut,
      pOutSize,
      MCUXCLHASHMODES_REQ_SGI | MCUXCLHASHMODES_REQ_DMA_INPUT | MCUXCLHASHMODES_REQ_DMA_OUTPUT
    ));

    /* Set expectations and exit */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking_Core, MCUXCLHASH_STATUS_OK);
}

/**
 * @brief Oneshot Compute Skeleton core implementation for DMA non-blocking Sha2 with SGI support
 *
 * Data Integrity: Expunge(pIn + inSize + pOut + pOutSize)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking, mcuxClHash_AlgoSkeleton_OneShot_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking (
                        mcuxClSession_Handle_t session,
                        mcuxClHash_Algo_t algorithm,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize,
                        mcuxCl_Buffer_t pOut,
                        uint32_t *const pOutSize
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking_Core));
    MCUX_CSSL_FP_FUNCTION_CALL(ret, mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking_Core(session, algorithm, pIn, inSize, pOut, pOutSize));


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_Sgi_oneShot_Sha2_DmaNonBlocking, ret);
}


/**
 * @brief Hash modes Sha2 non-blocking ending and cleanup operations. This function stores remaing part of data which
 *        is not sufficient to fill complete block. It needs to be run as a step of
 *        Sha2 SGI non-blocking processing stage as it expects full blocks to be handled already.
 *
 *
 * This function performs following Sha2 operations
 *  - store state in context when full block was processed during prevoius stages
 *  - copy input to accumulation buffer
 *  - mcuxClSgi_Drv_close
 *  - release SGI and DMA input
 *
 * @param[in]       session             Handle for the current CL session
 * @param[in]       context             Hash algorithm that should be used during the operations
 * @param[in]       pIn                 Pointer to input buffer object
 * @param[in]       inSize              Input size, where algoBlockSize > inSize
 * @param[out]      inOffset            Offset in buffer object
 * @param[out]      dataToCopyLength    Size indicating if data had to be transferred to unprocessed buffer
 *                                      during previous processing stages
 *
 * @return void
 *
 * @note Function uses early-exit mechanism with following return codes:
 *       - MCUXCLHASH_STATUS_FAILURE - if the number of processed blocks is incorrect.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sgi_process_StoreRemainingData_Sha2_DmaNonBlocking)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_Sgi_process_StoreRemainingData_Sha2_DmaNonBlocking (
                        mcuxClSession_Handle_t session,
                        mcuxClHash_Context_t context,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize,
                        uint32_t inOffset,
                        uint32_t dataToCopyLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sgi_process_StoreRemainingData_Sha2_DmaNonBlocking);

    uint8_t *pUnprocessed = (uint8_t *)mcuxClHash_getUnprocessedPtr(context);
    uint32_t *pState = mcuxClHash_getStatePtr(context);

    /* If just 1 block processed, update state in context */
    if (((0u < dataToCopyLength) && (0u == context->unprocessedLength)))
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());
        /* Wait until SGI has finished */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());
        /* Extract state from SGI and put it into context */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storePartialHash));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storePartialHash(pState, context->algo->stateSize));
        /* Check whether number of processed blocks is correct */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_checkHashCounter));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_checkHashCounter(session, 1u));
    }
    /* 0 < inSize < blockSize*/
    if (0u < inSize)
    {
        /* Balance DI impact of mcuxClBuffer_read. */
        MCUX_CSSL_DI_RECORD(bufferRead2Balancing, pIn);
        MCUX_CSSL_DI_RECORD(bufferRead2Balancing, inOffset);
        MCUX_CSSL_DI_RECORD(bufferRead2Balancing, pUnprocessed);
        MCUX_CSSL_DI_RECORD(bufferRead2Balancing, inSize);

        /* Copy input to accumulation buffer */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
        /* Error handled inside mcuxClBuffer_read */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, inOffset, pUnprocessed, inSize));

        /* Update context data / input pointer */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("the result does not wrap ")
        context->unprocessedLength += inSize;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_close));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_close(session));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRelease));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRelease(session, MCUXCLHASHMODES_REQ_SGI | MCUXCLHASHMODES_REQ_DMA_INPUT));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHashModes_Sgi_process_StoreRemainingData_Sha2_DmaNonBlocking);
}


/**
 * @brief Process Skeleton implementation for DMA non-blocking Sha2 with SGI support
 *
 * Data Integrity: Expunge(context + pIn + inSize)
 *
 * @note Function uses early-exit mechanism with following return codes:
 *       - MCUXCLHASH_STATUS_FULL - when the total input size exceeds the upper limit.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sgi_process_Sha2_DmaNonBlocking, mcuxClHash_AlgoSkeleton_Process_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_Sgi_process_Sha2_DmaNonBlocking (
                        mcuxClSession_Handle_t session,
                        mcuxClHash_Context_t context,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sgi_process_Sha2_DmaNonBlocking);

    /******************************************************************************************************
     * Step 1: Initialize SGI to perform Hash operation of dedicated algorithm if no data processed yet.
     * Initialize Hash counter in SGI and local variables
     ******************************************************************************************************/
    const uint32_t fullSize = inSize;
    uint32_t *pUnprocessed = mcuxClHash_getUnprocessedPtr(context);
    uint8_t *pUnprocessedBytes = (uint8_t *)pUnprocessed;
    uint32_t *pState = mcuxClHash_getStatePtr(context);
    const mcuxClHash_AlgorithmDescriptor_t *algorithm = context->algo;
    const mcuxClHashModes_Internal_AlgorithmDescriptor_t *algorithmDetails = (const mcuxClHashModes_Internal_AlgorithmDescriptor_t *) context->algo->pAlgorithmDetails;
    const size_t algoBlockSize = context->algo->blockSize;
    // TODO CLNS-16738: please check
    //MCUX_CSSL_FP_COUNTER_STMT(const uint32_t expectedNumberOfCopyOperations = ((context->unprocessedLength + inSize % algoBlockSize) > 0u ? 1u : 0u) + (context->unprocessedLength > 0u ? 1u : 0u));

    /* Request resources */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRequest));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRequest(
      session,
      mcuxClHashModes_Sha2Sgi_ISR_Multipart,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_Sha2Sgi_ISR_Multipart),
      MCUXCLHASHMODES_REQ_SGI | MCUXCLHASHMODES_REQ_DMA_INPUT
    ));

    /* Don't check the return value since it always return OK */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));

    /* Initialize state with IV */
    int processedAlreadyOneBlock = mcuxClHash_processedLength_cmp(context->processedLength, algoBlockSize);
    if (0 > processedAlreadyOneBlock)
    {
        /* Configure respective SHA-2 in normal mode using standard IV */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiUtilsInitHash);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiUtilsInitHash(NULL, MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV));
    }
    else
    {
        /* Configure respective SHA-2 in normal mode using pState as IV */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiUtilsInitHash);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiUtilsInitHash(pState, MCUXCLSGI_UTILS_AUTO_MODE_LOAD_IV));
    }

    /* Enable counter, to count number of blocks processed by SGI in this call */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableHashCounter(0u));

    /* Compute counter increase, considering the amount of unprocessed data now and at the end of this function. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("It is ensured that unprocessedLength < algoBlockSize and (counterIncreaseInBlocks - 1u) * algoBlockSize < UINT32_MAX. ")
    uint32_t counterIncreaseInBlocks = (inSize / algoBlockSize)
                                + ((inSize % algoBlockSize) + (context->unprocessedLength % algoBlockSize)) / algoBlockSize;
    if((counterIncreaseInBlocks * algoBlockSize) < counterIncreaseInBlocks)
    {
        /* Prevent overflow by adding counter increase in two parts. */
        mcuxClHash_processedLength_add(context->processedLength, (counterIncreaseInBlocks - 1u) * algoBlockSize);
        mcuxClHash_processedLength_add(context->processedLength, algoBlockSize);
    }
    else
    {
        mcuxClHash_processedLength_add(context->processedLength, counterIncreaseInBlocks * algoBlockSize);
    }
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    /* Verify that the processed length will not exceed the algorithm's maximum allowed length. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("This index computation cannot wrap")
    uint8_t counterHighestByte = ((uint8_t *) context->processedLength)[algorithm->counterSize - 1u];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    if(0u != (counterHighestByte & algorithm->processedLengthCheckMask))
    {
        MCUXCLSESSION_ERROR(session, MCUXCLHASH_STATUS_FULL);
    }

    /**************************************************************************************
     * Step 2: Process input data
     **************************************************************************************/

    /* All blocks can be processed in bulk directly from pIn */
    /* If anything in pUnprocessed, first it needs to be filled up to blockSize and processed. Only then input can be passed into the SGI register */
    uint32_t dataToCopyLength = 0u;
    uint32_t inOffset = 0u;
    if(context->unprocessedLength > 0u)
    {
        /* Take into account something might be already in unprocessed buffer */
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(context->unprocessedLength, 0u, algoBlockSize, MCUXCLHASH_STATUS_FAULT_ATTACK);
        dataToCopyLength = (inSize < (algoBlockSize - context->unprocessedLength)) ? inSize : (algoBlockSize - context->unprocessedLength);

        /* Balance DI impact of mcuxClBuffer_read. */
        MCUX_CSSL_DI_RECORD(bufferRead1Balancing, pIn);
        MCUX_CSSL_DI_RECORD(bufferRead1Balancing, inOffset);
        MCUX_CSSL_DI_RECORD(bufferRead1Balancing, pUnprocessedBytes + context->unprocessedLength);
        MCUX_CSSL_DI_RECORD(bufferRead1Balancing, dataToCopyLength);
        /* Copy input to accumulation buffer */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
        /* Error handled inside mcuxClBuffer_read */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, inOffset, pUnprocessedBytes + context->unprocessedLength, dataToCopyLength));

        /* Update counter / context data / input pointer */
        inSize -= dataToCopyLength;
        inOffset += dataToCopyLength;
        context->unprocessedLength += dataToCopyLength;

        /* If whole unprocessed buffer filled, process block and update context data*/
        if(context->unprocessedLength == algoBlockSize)
        {
            /* Wait until SGI is ready to take input */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

            /* Start SGI SHA2 processing */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(pUnprocessed, algorithm->blockSize));
            /* Update necessary context data, prepare for block processing */
            context->unprocessedLength = 0u;
        }
    }

    /* Process whole blocks */
    uint32_t numberOfFullBlocks = inSize / algoBlockSize;
    if (algoBlockSize <= inSize)
    {
        mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);

        /* check if SGI has already started because it can't wait more than once after it start */
        if (!((0u < dataToCopyLength) && (0u == context->unprocessedLength)))
        {
            /* Wait until SGI is ready to take input */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

            /* Start SGI SHA2 processing */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));
        }


        /* Load input data to FIFO register banks */
        /* Configure the DMA channels */
        MCUXCLBUFFER_DERIVE_RO(pInWithOffset, pIn, inOffset);
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("numberOfFullBlocks * algorithm->blockSize is less than MAX of uint32_t regarding to initialization above")
        mcuxClDma_Utils_configureSgiSha2InputChannel(session,
                                                    MCUXCLBUFFER_GET(pInWithOffset),
                                                    numberOfFullBlocks * algorithm->blockSize);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

        /* Enable interrupts for the completion of the input channel and for errors */
        mcuxClDma_Drv_enableChannelDoneInterrupts(inputChannel);
        mcuxClDma_Drv_enableErrorInterrupts(inputChannel);

        mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t *isrCtx = mcuxClHashModes_castToSha2MultipartInternalIsrCtx(mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t))));

        isrCtx->inSize = inSize;
        isrCtx->inputBuf = pIn;
        isrCtx->inputOffset = inOffset;
        isrCtx->numberOfFullBlocks = numberOfFullBlocks;
        isrCtx->ctx = context;
        mcuxClSession_job_setClWorkarea(session, isrCtx);
        /* Enable the DMA */
        mcuxClDma_Drv_startChannel(inputChannel);

        MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, context);
        MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, pIn);
        MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, fullSize);

        /* Early exit for non-blocking mode */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_Sgi_process_Sha2_DmaNonBlocking, MCUXCLHASH_STATUS_JOB_STARTED);
    }
    else
    {
        MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, context);
        MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, pIn);
        MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, fullSize);

        MCUX_CSSL_ANALYSIS_START_SUPPRESS_OVERFLOWED_TRUNCATED_STATUS_CODE()

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_Sgi_process_StoreRemainingData_Sha2_DmaNonBlocking));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_Sgi_process_StoreRemainingData_Sha2_DmaNonBlocking(
          session,
          context,
          pIn,
          inSize,
          inOffset,
          dataToCopyLength
        ));
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_Sgi_process_Sha2_DmaNonBlocking, MCUXCLHASH_STATUS_OK);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OVERFLOWED_TRUNCATED_STATUS_CODE()
    }
}


/**********************************************************
 * Algorithm descriptor implementations
 **********************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha224 =
{
    .sgiUtilsInitHash                 = mcuxClSgi_Utils_initSha224,
    .protectionToken_sgiUtilsInitHash = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_initSha224),
    .sgiLoadInternalDataBlock         = mcuxClSgi_Utils_load512BitBlock,
    .protectionToken_sgiLoadInternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock),
    .sgiLoadExternalDataBlock         = mcuxClSgi_Utils_load512BitBlock_buffer,
    .protectionToken_sgiLoadExternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock_buffer),
};

MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(MCUXCLHASHMODES_DESCRIPTOR_NONBLOCKING_SHA_224, &mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha224);


static const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha256 =
{
    .sgiUtilsInitHash                 = mcuxClSgi_Utils_initSha256,
    .protectionToken_sgiUtilsInitHash = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_initSha256),
    .sgiLoadInternalDataBlock         = mcuxClSgi_Utils_load512BitBlock,
    .protectionToken_sgiLoadInternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock),
    .sgiLoadExternalDataBlock         = mcuxClSgi_Utils_load512BitBlock_buffer,
    .protectionToken_sgiLoadExternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock_buffer),
};

MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(MCUXCLHASHMODES_DESCRIPTOR_NONBLOCKING_SHA_256, &mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha256);


static const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha384 =
{
    .sgiUtilsInitHash                 = mcuxClSgi_Utils_initSha384,
    .protectionToken_sgiUtilsInitHash = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_initSha384),
    .sgiLoadInternalDataBlock         = mcuxClSgi_Utils_load1024BitBlock,
    .protectionToken_sgiLoadInternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load1024BitBlock),
    .sgiLoadExternalDataBlock         = mcuxClSgi_Utils_load1024BitBlock_buffer,
    .protectionToken_sgiLoadExternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load1024BitBlock_buffer),
};

MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(MCUXCLHASHMODES_DESCRIPTOR_NONBLOCKING_SHA_384, &mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha384);


static const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha512 =
{
    .sgiUtilsInitHash                 = mcuxClSgi_Utils_initSha512,
    .protectionToken_sgiUtilsInitHash = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_initSha512),
    .sgiLoadInternalDataBlock         = mcuxClSgi_Utils_load1024BitBlock,
    .protectionToken_sgiLoadInternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load1024BitBlock),
    .sgiLoadExternalDataBlock         = mcuxClSgi_Utils_load1024BitBlock_buffer,
    .protectionToken_sgiLoadExternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load1024BitBlock_buffer),
};

MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(MCUXCLHASHMODES_DESCRIPTOR_NONBLOCKING_SHA_512, &mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha512);



MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
