/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClBuffer.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClHashModes_Internal_Resource_Common.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClHashModes_Internal_sgi_sha2_common.h>

/**********************************************************
 * Helper functions
 **********************************************************/

/**********************************************************
 * *INTERNAL* layer functions
 **********************************************************/

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sgi_oneShot_Sha2, mcuxClHash_AlgoSkeleton_OneShot_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_Sgi_oneShot_Sha2 (
                        mcuxClSession_Handle_t session,
                        mcuxClHash_Algo_t algorithm,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize,
                        mcuxCl_Buffer_t pOut,
                        uint32_t *const pOutSize
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sgi_oneShot_Sha2);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(algorithm->hashSize, MCUXCLHASH_OUTPUT_SIZE_SHA_224, MCUXCLHASH_OUTPUT_SIZE_SHA_512, MCUXCLHASH_STATUS_INVALID_PARAMS)
    MCUX_CSSL_DI_RECORD(storeHashResultBalancing, pOut);
    MCUX_CSSL_DI_RECORD(storeHashResultBalancing, algorithm->hashSize);

    /**************************************************************************************
     * Step 1: Initialize SGI to perform Hash operation of dedicated algorithm
     **************************************************************************************/

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    const mcuxClHashModes_Internal_AlgorithmDescriptor_t *algorithmDetails = (const mcuxClHashModes_Internal_AlgorithmDescriptor_t *) algorithm->pAlgorithmDetails;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    /* Error handled inside HwRequest */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRequest));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRequest(session, NULL, 0U, MCUXCLHASHMODES_REQ_SGI));

    /* Don't check the return value since it always return OK */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));

    /* Configure respective SHA-2 in normal mode using standard IV */
    MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiUtilsInitHash);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiUtilsInitHash(session, NULL, MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV));

    /* Enable counter, to count number of blocks processed by SGI */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableHashCounter(0u));

    /**************************************************************************************
     * Step 2: Process full blocks of input data
     **************************************************************************************/

    /* All blocks can be processed in bulk directly from in */
    uint32_t offset = 0u;

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(algorithm->blockSize, MCUXCLHASH_BLOCK_SIZE_SHA_224, MCUXCLHASH_BLOCK_SIZE_SHA_512, MCUXCLHASH_STATUS_INVALID_PARAMS)
    uint32_t numberOfFullBlocks = inSize / algorithm->blockSize;
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(numberOfFullBlocks, 0u, UINT32_MAX / MCUXCLHASH_BLOCK_SIZE_SHA_224, MCUXCLHASH_STATUS_INVALID_PARAMS)
    uint32_t counterFullBlocks = 0u;
    uint32_t firstSgiOp = MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP;

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("numberOfFullBlocks is less than MAX of uint32_t even increased by 1")
    uint32_t expectedSgiCounter = numberOfFullBlocks + 1u;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    MCUX_CSSL_DI_RECORD(fullBlocksLoopIterations, numberOfFullBlocks);
    while (counterFullBlocks < numberOfFullBlocks)
    {
        /* Wait until SGI is ready to take input and check for SGI SHA error */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

        /* Load input data to DATIN and KEY register banks */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiLoadInternalDataBlock);

        MCUX_CSSL_ANALYSIS_START_SUPPRESS_UNALIGNED_ACCESS()
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiLoadInternalDataBlock((const uint32_t *) (pIn + offset)));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_UNALIGNED_ACCESS()

        /* Start SGI SHA2 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(offset, 0u, (numberOfFullBlocks - 1u) * algorithm->blockSize, MCUXCLHASH_STATUS_INVALID_PARAMS)
        offset += algorithm->blockSize;
        counterFullBlocks++;
        /* Check whether the number of processed blocks reached the max value allowed in SGI->COUNT */
        if(MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE_IN_LOOP == counterFullBlocks)
        {
            /* Wait until SGI has finished and check for SGI SHA error */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

            /* Check whether number of processed blocks is correct */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_checkHashCounter));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_checkHashCounter(session, MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE_IN_LOOP));

            /* Reset counters if max value is reached */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableHashCounter));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableHashCounter(0u));
            counterFullBlocks = 0u;
            numberOfFullBlocks -= MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE_IN_LOOP;
        }

        /* Disable IV load after the first block has been processed */
        if(MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP == firstSgiOp)
        {
            /* Wait until SGI has finished and check for SGI SHA error */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

            /* Disable SGI initialization with standard IV */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableIvAutoInit));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableIvAutoInit());

            firstSgiOp = MCUXCLHASHMODES_INTERNAL_SGI_SHA2_SUBSEQUENT_SGI_OP;
        }
        MCUX_CSSL_DI_EXPUNGE(fullBlocksLoopIterations, 1u);
    }

    /**************************************************************************************
     * Step 3: Pad the input data and process last block
     **************************************************************************************/

    /* Buffer in CPU WA to store the last block of data in the finalization phase */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
    MCUX_CSSL_FP_FUNCTION_CALL(uint32_t*, shaBlock, mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize)));
    uint8_t *shaBlockBytes = (uint8_t *)shaBlock;

    size_t sizeRemainingBlock = inSize & (algorithm->blockSize - 1u);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(sizeRemainingBlock, 0u, MCUXCLHASH_BLOCK_SIZE_SHA_512 - 1U, MCUXCLHASH_STATUS_INVALID_PARAMS)

    /* pIn is deliberately not recorded for sumOfBufferReadParams,
     * because mcuxClHashModes_Sgi_oneShot_Sha2 is supposed to expunge pIn.
     */
    MCUX_CSSL_DI_RECORD(sumOfBufferReadParams, offset);
    MCUX_CSSL_DI_RECORD(sumOfBufferReadParams, shaBlock);
    MCUX_CSSL_DI_RECORD(sumOfBufferReadParams, sizeRemainingBlock);
    /* Copy the data to the buffer in the workspace. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, offset, shaBlockBytes, sizeRemainingBlock));

    /* add first byte of the padding: (remaining) < (block length) so there is space in the buffer */
    shaBlockBytes[sizeRemainingBlock] = 0x80u;
    sizeRemainingBlock += 1u;
    uint32_t numberOfZeroBytes = algorithm->blockSize - sizeRemainingBlock;

    /* Process partial padded block if needed */
    if (algorithm->counterSize > numberOfZeroBytes) // need room for 64 bit counter and one additional byte
    {
        MCUX_CSSL_DI_RECORD(setShablock1, &shaBlockBytes[sizeRemainingBlock]);
        MCUX_CSSL_DI_RECORD(setShablock1, numberOfZeroBytes);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(&shaBlockBytes[sizeRemainingBlock], 0x00u, numberOfZeroBytes));

        /* Wait until SGI is ready to take input and check for SGI SHA error */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

        /* Load input data to DATIN and KEY register banks */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiLoadInternalDataBlock);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiLoadInternalDataBlock(shaBlock));

        /* Start SGI SHA2 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        if(MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP == firstSgiOp)
        {
            /* Wait until SGI has finished and check for SGI SHA error */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

            /* Disable SGI initialization with standard IV */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableIvAutoInit));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableIvAutoInit());
        }

        sizeRemainingBlock = 0u;
        numberOfZeroBytes = algorithm->blockSize;
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("expectedSgiCounter is less than MAX of uint32_t even increased by 1")
        expectedSgiCounter += 1u;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    }

    /* Perform padding by adding data counter */
    MCUX_CSSL_DI_RECORD(setShablock2, &shaBlockBytes[sizeRemainingBlock]);
    MCUX_CSSL_DI_RECORD(setShablock2, numberOfZeroBytes);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(&shaBlockBytes[sizeRemainingBlock], 0x00u, numberOfZeroBytes));

    sizeRemainingBlock = algorithm->blockSize;
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize <<  3u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >>  5u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >> 13u) & 0xFFu);
    shaBlockBytes[--sizeRemainingBlock] = (uint8_t)((inSize >> 21u) & 0xFFu);
    shaBlockBytes[sizeRemainingBlock - 1u] = (uint8_t)(inSize >> 29u);

    /* Wait until SGI is ready to take input and check for SGI SHA error */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

    /* Load input data to DATIN and KEY register banks */
    MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiLoadInternalDataBlock);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiLoadInternalDataBlock(shaBlock));

    /* Start SGI SHA2 processing */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

    /**************************************************************************************
     * Step 4: Copy result to output buffers
     **************************************************************************************/

    /* Wait until SGI has finished check for SGI SHA error */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

    /* Check whether number of processed blocks is correct */
    expectedSgiCounter = expectedSgiCounter % MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE_IN_LOOP;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_checkHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_checkHashCounter(session, expectedSgiCounter));

    /* Copy hash digest to output buffer */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storeHashResult));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storeHashResult(session, pOut, algorithm->hashSize));

    *pOutSize = algorithm->hashSize;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_close));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_close(session));

    /* Free workarea (shaBlock) */
    mcuxClSession_freeWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize));

    /* pIn already expunged by sumOfBufferReadParams. */
    MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, inSize);
    MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, pOut);
    MCUX_CSSL_DI_EXPUNGE(oneshotSkeletonParams, pOutSize);

    /* Release and exit */
	MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRelease));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRelease(session, MCUXCLHASHMODES_REQ_SGI));

    /* Set expectations and exit */
    /* FP balancing is outdated */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_Sgi_oneShot_Sha2, MCUXCLHASH_STATUS_OK);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sgi_process_Sha2, mcuxClHash_AlgoSkeleton_Process_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_Sgi_process_Sha2 (
                        mcuxClSession_Handle_t session,
                        mcuxClHash_Context_t context,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sgi_process_Sha2);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(context->algo->blockSize, MCUXCLHASH_BLOCK_SIZE_MD, MCUXCLHASH_BLOCK_SIZE_MAX, MCUXCLHASH_STATUS_INVALID_INPUT);

    const uint32_t fullSize = inSize;

    /******************************************************************************************************
     * Step 1: Initialize SGI to perform Hash operation of dedicated algorithm if no data processed yet.
     * Initialize Hash counter in SGI and local variables
     ******************************************************************************************************/
    uint32_t offset = 0u;
    uint32_t *pUnprocessed = mcuxClHash_getUnprocessedPtr(context);
    uint8_t *pUnprocessedBytes = (uint8_t *)pUnprocessed;
    uint32_t *pState = mcuxClHash_getStatePtr(context);
    const mcuxClHash_AlgorithmDescriptor_t *algorithm = context->algo;
    const mcuxClHashModes_Internal_AlgorithmDescriptor_t *algorithmDetails = (const mcuxClHashModes_Internal_AlgorithmDescriptor_t *) context->algo->pAlgorithmDetails;
    const size_t algoBlockSize = context->algo->blockSize;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("numberOfFullBlocks cannot overflow for any combination of inSize and algorithm. ")
    uint32_t numberOfFullBlocks = (inSize / algorithm->blockSize)
                        + ((inSize % algorithm->blockSize)
                        + (context->unprocessedLength % algorithm->blockSize)) / algorithm->blockSize;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    uint8_t toProcessAtLeastOneBlock = (numberOfFullBlocks > 0u) ? 1u : 0u;
    uint32_t counterBlocks = 0u;

    /* Error handled inside HwRequest */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRequest));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRequest(session, NULL, 0U, MCUXCLHASHMODES_REQ_SGI));

    /* Don't check the return value since it always return OK */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));

    uint32_t firstSgiOp = MCUXCLHASHMODES_INTERNAL_SGI_SHA2_SUBSEQUENT_SGI_OP;

    /* Initialize state with IV */
    int processedAlreadyOneBlock = mcuxClHash_processedLength_cmp(context->processedLength, algoBlockSize);
    if (0 > processedAlreadyOneBlock)
    {
        /* Configure respective SHA-2 in normal mode using standard IV */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiUtilsInitHash);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiUtilsInitHash(session, NULL, MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV));

        firstSgiOp = MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP;
    }
    else
    {
        /* Configure respective SHA-2 in normal mode using pState as IV */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiUtilsInitHash);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiUtilsInitHash(session, pState, MCUXCLSGI_UTILS_NORMAL_MODE_LOAD_IV));
    }

    /* Enable counter, to count number of blocks processed by SGI in this call */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableHashCounter(0u));

    /* Compute counter increase, considering the amount of unprocessed data now and at the end of this function. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("the result does not wrap")
    uint32_t counterIncrease = (inSize + context->unprocessedLength) - ( (inSize + context->unprocessedLength) % algorithm->blockSize);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    mcuxClHash_processedLength_add(context->processedLength, counterIncrease);

    /* Verify that the processed length will not exceed the algorithm's maximum allowed length. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("algorithm->counterSize is greater than 1")
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
    if(context->unprocessedLength > 0u)
    {
        /* Take into account something might be already in unprocessed buffer */
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(context->unprocessedLength, 0u, algoBlockSize, MCUXCLHASH_STATUS_FAULT_ATTACK);
        uint32_t dataToCopyLength = (inSize < (algoBlockSize - context->unprocessedLength)) ? inSize : (algoBlockSize - context->unprocessedLength);
        MCUX_CSSL_DI_RECORD(sumOfBufferRead1Params, pIn);
        MCUX_CSSL_DI_RECORD(sumOfBufferRead1Params, offset);
        MCUX_CSSL_DI_RECORD(sumOfBufferRead1Params, (pUnprocessedBytes + context->unprocessedLength));
        MCUX_CSSL_DI_RECORD(sumOfBufferRead1Params, dataToCopyLength);
        /* Copy input to accumulation buffer */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn,
                                                        offset,
                                                        pUnprocessedBytes + context->unprocessedLength,
                                                        dataToCopyLength));

        /* Update counter / context data / input pointer */
        inSize -= dataToCopyLength;
        offset += dataToCopyLength;
        context->unprocessedLength += dataToCopyLength;

        /* If whole unprocessed buffer filled, process block and update context data*/
        if(context->unprocessedLength == algoBlockSize)
        {
            /* Wait until SGI is ready to take input and check for SGI SHA error */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

            /* Update necessary context data, prepare for block processing */
            MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiLoadInternalDataBlock);
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiLoadInternalDataBlock(pUnprocessed));
            context->unprocessedLength = 0u;

            /* Start SGI SHA2 processing */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

            if(MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP == firstSgiOp)
            {
                /* Wait until SGI has finished check for SGI SHA error */
                MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
                MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

                /* Disable SGI initialization with standard IV */
                MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableIvAutoInit));
                MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableIvAutoInit());

                firstSgiOp = MCUXCLHASHMODES_INTERNAL_SGI_SHA2_SUBSEQUENT_SGI_OP;
            }
            counterBlocks = 1u;
        }
    }

    /* Process whole blocks */
    MCUX_CSSL_DI_RECORD(WholeBlocksLoopIterations, inSize / algoBlockSize);
    while(algoBlockSize <= inSize) /* Also process the last full block */
    {
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(offset, 0U, dataToCopyLength + algoBlockSize * WholeBlocksLoopIterations, MCUXCLHASH_STATUS_FAULT_ATTACK);

        /* Wait until SGI is ready to take input and check for SGI SHA error */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

        /* Update necessary context data, prepare for block processing */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Offset cannot overflow")

        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiLoadInternalDataBlock);

        MCUX_CSSL_ANALYSIS_START_SUPPRESS_UNALIGNED_ACCESS()
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiLoadInternalDataBlock((const uint32_t *) (pIn + offset)));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_UNALIGNED_ACCESS()

        offset += algoBlockSize;
        inSize -= algoBlockSize;
        context->unprocessedLength = 0u;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

        /* Start SGI SHA2 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));
        counterBlocks++;
        /* Check whether the number of processed blocks reached the max value allowed in SGI->COUNT */
        if(MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE_IN_LOOP == counterBlocks)
        {
            /* Wait until SGI has finished check for SGI SHA error */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

            /* Check whether number of processed blocks is correct */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_checkHashCounter));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_checkHashCounter(session, MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE_IN_LOOP));

            /* Reset counters if max value is reached */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableHashCounter));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableHashCounter(0u));
            counterBlocks = 0u;
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("the result does not wrap ")
            numberOfFullBlocks -= MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE_IN_LOOP;
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
        }

        if(MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP == firstSgiOp)
        {
            /* Wait until SGI has finished check for SGI SHA error */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

            /* Disable SGI initialization with standard IV */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableIvAutoInit));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableIvAutoInit());

            firstSgiOp = MCUXCLHASHMODES_INTERNAL_SGI_SHA2_SUBSEQUENT_SGI_OP;
        }
        MCUX_CSSL_DI_EXPUNGE(WholeBlocksLoopIterations, 1u);
    }

    /* If at least 1 block processed, update state in context */
    if (toProcessAtLeastOneBlock > 0u)
    {
        /* Wait until SGI has finished and check for SGI SHA error */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

        /* Extract state from SGI and put it into context */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storePartialHash));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storePartialHash(pState, context->algo->stateSize));
    }
    /* 0 < inSize < blockSize*/
    if(0u < inSize)
    {
        /* Take into account something might be already in unprocessed buffer */
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(context->unprocessedLength, 0u, algoBlockSize, MCUXCLHASH_STATUS_FAULT_ATTACK);
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(offset, algoBlockSize * WholeBlocksLoopIterations, dataToCopyLength + algoBlockSize * WholeBlocksLoopIterations, MCUXCLHASH_STATUS_FAULT_ATTACK);
        uint32_t dataToCopyLength = (inSize < (algoBlockSize - context->unprocessedLength)) ? inSize : (algoBlockSize - context->unprocessedLength);
        MCUX_CSSL_DI_RECORD(sumOfBufferRead2Params, pIn);
        MCUX_CSSL_DI_RECORD(sumOfBufferRead2Params, offset);
        MCUX_CSSL_DI_RECORD(sumOfBufferRead2Params, (pUnprocessedBytes + context->unprocessedLength));
        MCUX_CSSL_DI_RECORD(sumOfBufferRead2Params, dataToCopyLength);
        /* Copy input to accumulation buffer */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Offset cannot overflow")
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn,
                                                        offset,
                                                        pUnprocessedBytes + context->unprocessedLength,
                                                        dataToCopyLength));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

        /* Update context data / input pointer */
        context->unprocessedLength += dataToCopyLength;
    }

    /* Check whether number of processed blocks is correct */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_checkHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_checkHashCounter(session, numberOfFullBlocks));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_close));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_close(session));

    MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, context);
    MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, pIn);
    MCUX_CSSL_DI_EXPUNGE(processSkeletonParams, fullSize);

    /* Release and exit */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRelease));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRelease(session, MCUXCLHASHMODES_REQ_SGI));

    /* Set expectations and exit */
    /* FP balancing is outdated */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_Sgi_process_Sha2, MCUXCLHASH_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_Sgi_finish_Sha2, mcuxClHash_AlgoSkeleton_Finish_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_Sgi_finish_Sha2(mcuxClSession_Handle_t session,
                                                                mcuxClHash_Context_t context,
                                                                mcuxCl_Buffer_t pOut,
                                                                uint32_t* const pOutSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_Sgi_finish_Sha2);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(context->algo->blockSize, MCUXCLHASH_BLOCK_SIZE_MD, MCUXCLHASH_BLOCK_SIZE_MAX, MCUXCLHASH_STATUS_INVALID_INPUT);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(context->algo->stateSize, MCUXCLHASH_STATE_SIZE_MIN, MCUXCLHASH_STATE_SIZE_MAX, MCUXCLHASH_STATUS_INVALID_INPUT);

    /* context is deliberately not recorded for clearContext,
     * because mcuxClHashModes_Sgi_finish_Sha2 is supposed to expunge context.
     */
    MCUX_CSSL_DI_RECORD(clearContext, sizeof(mcuxClHash_ContextDescriptor_t) + context->algo->blockSize + context->algo->stateSize);

    uint32_t *pUnprocessed = mcuxClHash_getUnprocessedPtr(context);
    uint8_t *pUnprocessedBytes = (uint8_t *)pUnprocessed;
    uint32_t *pState = mcuxClHash_getStatePtr(context);

    const size_t algoBlockSize = context->algo->blockSize;
    const mcuxClHash_AlgorithmDescriptor_t *algorithm = context->algo;
    const mcuxClHashModes_Internal_AlgorithmDescriptor_t *algorithmDetails = (const mcuxClHashModes_Internal_AlgorithmDescriptor_t *) context->algo->pAlgorithmDetails;

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(algorithm->hashSize, MCUXCLHASH_OUTPUT_SIZE_SHA_224, MCUXCLHASH_OUTPUT_SIZE_SHA_512, MCUXCLHASH_STATUS_INVALID_PARAMS)
    MCUX_CSSL_DI_RECORD(storeHashResultBalancing, pOut);
    MCUX_CSSL_DI_RECORD(storeHashResultBalancing, algorithm->hashSize);
    
    /* Error hanlded inside HwRequest */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRequest));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRequest(session, NULL, 0U, MCUXCLHASHMODES_REQ_SGI));

    /* Don't check the return value since it always return OK */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));

    uint32_t firstSgiOp = MCUXCLHASHMODES_INTERNAL_SGI_SHA2_SUBSEQUENT_SGI_OP;
    int processedAlreadyOneBlock = mcuxClHash_processedLength_cmp(context->processedLength, algoBlockSize);
    if (0 > processedAlreadyOneBlock)
    {
        /* Configure respective SHA-2 in normal mode using standard IV */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiUtilsInitHash);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiUtilsInitHash(session, NULL, MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV));

        firstSgiOp = MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP;
    }
    else
    {
        /* Configure respective SHA-2 in normal mode using pState as IV */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiUtilsInitHash);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiUtilsInitHash(session, pState, MCUXCLSGI_UTILS_NORMAL_MODE_LOAD_IV));
    }
    /* Enable counter, to count number of blocks processed by SGI in this call*/
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableHashCounter(0u));

    /* No further input to be added, processedLength can be updated now. Will be used for final length value attached inside padding */
    mcuxClHash_processedLength_add(context->processedLength, context->unprocessedLength);

    /* Verify that the processed length will not exceed the algorithm's maximum allowed length. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("index computation does not wrap. ")
    uint8_t counterHighestByte = ((uint8_t *) context->processedLength)[algorithm->counterSize - 1u];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    if(0u != (counterHighestByte & algorithm->processedLengthCheckMask))
    {
        MCUXCLSESSION_ERROR(session, MCUXCLHASH_STATUS_FULL);
    }

    /* Check whether context->unprocessedLength would wrap */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("the result of context->unprocessedLength is checked to avoid wrapping ")
    if(0u == context->unprocessedLength + 1u)
    {
        MCUXCLSESSION_FAULT(session, MCUXCLHASH_STATUS_FAULT_ATTACK);
    }

    pUnprocessedBytes[context->unprocessedLength++] = 0x80u; //set first bit of padding
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    uint32_t remainingBlockLength = algoBlockSize - (context->unprocessedLength);

    if(context->algo->counterSize > remainingBlockLength) // need room for 64 bit counter
    {
        /* Set remaining bytes in accumulation buffer to zero */
        MCUX_CSSL_DI_RECORD(setUnprocessed1, pUnprocessedBytes + context->unprocessedLength);
        MCUX_CSSL_DI_RECORD(setUnprocessed1, remainingBlockLength);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(pUnprocessedBytes + context->unprocessedLength, 0x00u, remainingBlockLength));

        /* Wait until SGI is ready to take input and check for SGI SHA error */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

        /* Load input data to DATIN and KEY register banks */
        MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiLoadInternalDataBlock);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiLoadInternalDataBlock(pUnprocessed));

        /* Start SGI SHA2 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        remainingBlockLength = algoBlockSize;
        context->unprocessedLength = 0u;

        if(MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP == firstSgiOp)
        {
            /* Wait until SGI has finished check for SGI SHA error */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

            /* Disable SGI initialization with standard IV */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableIvAutoInit));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableIvAutoInit());
        }
    }

    /* Set remaining bytes in accumulation buffer to zero */
    MCUX_CSSL_DI_RECORD(setUnprocessed2, pUnprocessedBytes + context->unprocessedLength);
    MCUX_CSSL_DI_RECORD(setUnprocessed2, remainingBlockLength);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(pUnprocessedBytes + context->unprocessedLength, 0x00u, remainingBlockLength));

    /* Perform padding by adding data counter - length is added from end of the array; byte-length is converted to bit-length */
    mcuxClHash_processedLength_toBits(context->processedLength);
    for(uint32_t i = 0u; i < algorithm->counterSize; ++i)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("blockSize is always large enough so that the index computation does not wrap. ")
        pUnprocessedBytes[algorithm->blockSize - i - 1u] = ((uint8_t*)context->processedLength)[i];
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    /* Wait until SGI is ready to take input and check for SGI SHA error */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

    /* Load input data to DATIN and KEY register banks */
    MCUX_CSSL_FP_EXPECT(algorithmDetails->protectionToken_sgiLoadInternalDataBlock);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(algorithmDetails->sgiLoadInternalDataBlock(pUnprocessed));

    /* Start SGI SHA2 processing */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

    uint32_t expectedSgiCounter = ((remainingBlockLength == algoBlockSize) ? 2u : 1u);

    *pOutSize = context->algo->hashSize;

    /* Wait until SGI has finished and check for SGI SHA error */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_Sha2_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_Sha2_wait(session));

    /* Check whether number of processed blocks is correct */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_checkHashCounter));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_checkHashCounter(session, expectedSgiCounter));

    /* Copy hash digest to output buffer */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storeHashResult));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storeHashResult(session, pOut, context->algo->hashSize));

    /* Clear context */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t*) context, sizeof(mcuxClHash_ContextDescriptor_t) + context->algo->blockSize + context->algo->stateSize));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_close));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_close(session));

    /* context already expunged by clearContext. */
    MCUX_CSSL_DI_EXPUNGE(finishSkeletonParams, pOut);
    MCUX_CSSL_DI_EXPUNGE(finishSkeletonParams, pOutSize);

    /* Release and exit */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_HwRelease));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_HwRelease(session, MCUXCLHASHMODES_REQ_SGI));

    /* FP balancing is outdated */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHashModes_Sgi_finish_Sha2);
}

/**********************************************************
 * Algorithm descriptor implementations
 **********************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(MCUXCLHASHMODES_DESCRIPTOR_SGI_SHA_224, &mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha224);

MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(MCUXCLHASHMODES_DESCRIPTOR_SGI_SHA_256, &mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha256);

MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(MCUXCLHASHMODES_DESCRIPTOR_SGI_SHA_384, &mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha384);

MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(MCUXCLHASHMODES_DESCRIPTOR_SGI_SHA_512, &mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha512);



MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
