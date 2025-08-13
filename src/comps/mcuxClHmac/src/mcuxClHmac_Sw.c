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

/** @file  mcuxClHMac_Sw.c
 *  @brief Implementation of SW engine functions for the HMAC component */

#include <mcuxClToolchain.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClMac.h>
#include <mcuxClSession.h>
#include <mcuxClMemory.h>
#include <mcuxClKey.h>
#include <mcuxClHmac.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal.h>
#include <internal/mcuxClHmac_Internal_Functions.h>
#include <internal/mcuxClHmac_Internal_Types.h>
#include <internal/mcuxClHmac_Core_Functions_Sw.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

#define MCUXCLMAC_HMAC_IPAD_BYTE (0x36u)
#define MCUXCLMAC_HMAC_OPAD_BYTE (0x5cu)

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_castToHashContext)
static mcuxClHash_Context_t mcuxClHmac_castToHashContext(uint32_t* pHashContext)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClHash_Context_t) pHashContext;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_Engine_Init_Sw, mcuxClHmac_InitEngine_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_Engine_Init_Sw(
    mcuxClSession_Handle_t session,
    mcuxClHmac_Context_Sw_t * const pContext
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_Engine_Init_Sw);

    const mcuxClHash_AlgorithmDescriptor_t *hashAlgo = ((mcuxClHmac_ModeDescriptor_t *) (pContext->common.pMode->pCustom))->hashAlgorithm;
    mcuxClKey_Descriptor_t * key = pContext->key;
    const uint32_t hashBlockSize = hashAlgo->blockSize;

    uint32_t keySize = mcuxClKey_getSize(key);
    uint8_t *pKeyData = NULL;
    /* Store pointer to raw key data in pKeyData. */
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(key));
    MCUXCLKEY_LOAD_FP(session, key, &pKeyData, NULL, MCUXCLKEY_ENCODING_SPEC_ACTION_PTR);

    size_t alreadyFilledKeyDataSize = 0u;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("hashBlockSize is less than PH_NCCLHASH_BLOCK_SIZE_MAX and hashBlockSize+4-1 is less than MAX of uint32_t")
    uint32_t hashBlockWordSize = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(hashBlockSize);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
    MCUX_CSSL_FP_FUNCTION_CALL(uint32_t*, pPreparedHmacKey, mcuxClSession_allocateWords_cpuWa(session, hashBlockWordSize));

    /*********************************************************************************************************/
    /* Prepare a block-sized key from the key given in the Hmac context (pContext) and store it in work area */
    /*********************************************************************************************************/
    if(keySize > hashBlockSize) /* key is too long */
    {
        MCUXCLBUFFER_INIT_RO(pKeyDataBuf, session, pKeyData, keySize);
        MCUXCLBUFFER_INIT_RW(pPreparedHmacKeyBuf, session, (uint8_t *)pPreparedHmacKey, hashBlockSize);
        uint32_t hashOutputSize = 0u;
        /* Given key must be hashed and then zero-padded up to hashBlockSize */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute));
        MCUX_CSSL_FP_FUNCTION_CALL(
          resultHashCompute,
          MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("MCUXCLKEY_LOAD_FP was called with MCUXCLKEY_ENCODING_SPEC_ACTION_PTR, which means the destination pointer is updated to point to the raw key data.")
          mcuxClHash_compute(session, hashAlgo, pKeyDataBuf, keySize, pPreparedHmacKeyBuf, &hashOutputSize)
          MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
        );
        MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashCompute);

        alreadyFilledKeyDataSize = hashAlgo->hashSize;
    }
    else /* key is not too long */
    {
        /* Balance DI for call to mcuxClMemory_copy_secure_int */
        MCUX_CSSL_DI_RECORD(memCopySecDst, (uint32_t) pPreparedHmacKey);
        MCUX_CSSL_DI_RECORD(memCopySecSrc, (uint32_t) pKeyData);
        MCUX_CSSL_DI_RECORD(memCopySecLen, (uint32_t) keySize);
        /* Given key must be zero-padded up to hashBlockSize */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int((uint8_t*)pPreparedHmacKey,
                                                                   pKeyData,
                                                                   keySize));
        alreadyFilledKeyDataSize = keySize;
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("the result does not wrap as there is no hash algo with hashAlgo->blockSize < hashAlgo->hashSize ")
    /* Balance DI for call to mcuxClMemory_set_int */
    MCUX_CSSL_DI_RECORD(memorySet, (uint32_t)pPreparedHmacKey + alreadyFilledKeyDataSize);
    MCUX_CSSL_DI_RECORD(memorySet, hashBlockSize - alreadyFilledKeyDataSize);
    /* Zero-pad the key */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int((uint8_t*)pPreparedHmacKey + alreadyFilledKeyDataSize,
                                                       0u,
                                                       hashBlockSize - alreadyFilledKeyDataSize));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    /***************************************************************************************************************/
    /* Store the prepared block-sized key in the Hmac context for later use in the outer hash during finalization  */
    /***************************************************************************************************************/
    /* Balance DI for call to mcuxClMemory_copy_secure_int */
    MCUX_CSSL_DI_RECORD(memCopySecDst, (uint32_t) pContext->preparedHmacKey);
    MCUX_CSSL_DI_RECORD(memCopySecSrc, (uint32_t) pPreparedHmacKey);
    MCUX_CSSL_DI_RECORD(memCopySecLen, (uint32_t) hashBlockSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int((uint8_t*)pContext->preparedHmacKey,
                                                               (uint8_t*)pPreparedHmacKey,
                                                               hashBlockSize));

    /********************************************************************/
    /* Initialize a Hash context for multipart within the Hmac context  */
    /********************************************************************/
    pContext->hashCtx = mcuxClHmac_castToHashContext(pContext->hashContextBuffer); /* The content of the hash context is stored in the Hmac context */

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init));
    MCUX_CSSL_FP_FUNCTION_CALL(resultHashInit, mcuxClHash_init(session, pContext->hashCtx, hashAlgo));
    MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashInit);

    /*****************************************************************************************************************/
    /* XOR the ipad to the block-sized key in the work area and Hash-process it (the first block of the inner hash)  */
    /*****************************************************************************************************************/
    /* Balance DI for call to mcuxClMemory_XORWithConst_secure_int */
    MCUX_CSSL_DI_RECORD(memoryXorWithConstCalls, 2u * (uint32_t)pPreparedHmacKey);
    MCUX_CSSL_DI_RECORD(memoryXorWithConstCalls, hashBlockSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XORWithConst_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XORWithConst_secure_int((uint8_t *)pPreparedHmacKey, (uint8_t *)pPreparedHmacKey, MCUXCLMAC_HMAC_IPAD_BYTE, hashBlockSize));

    MCUXCLBUFFER_INIT_RO(pPreparedHmacKeyInBuf, session, pPreparedHmacKey, hashBlockSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process));

    MCUX_CSSL_FP_FUNCTION_CALL(resultHashProcess, mcuxClHash_process(
      /* mcuxCLSession_Handle_t session: */ session,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("hashCTX is initialized by internal trusted function")
      /* mcuxClHash_Context_t context:   */ pContext->hashCtx,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
      /* mcuxCl_InputBuffer_t in:        */ pPreparedHmacKeyInBuf,
      /* uint32_t inSize:               */ hashBlockSize));
    MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashProcess);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_cleanupOnExit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHmac_cleanupOnExit(session, pPreparedHmacKey, hashBlockWordSize, hashBlockWordSize));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHmac_Engine_Init_Sw);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_Engine_Update_Sw, mcuxClHmac_UpdateEngine_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_Engine_Update_Sw(
    mcuxClSession_Handle_t session,
    mcuxClHmac_Context_Sw_t * const pContext,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_Engine_Update_Sw);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process));
    MCUX_CSSL_FP_FUNCTION_CALL(resultHashProcess, mcuxClHash_process(
      /* mcuxCLSession_Handle_t session: */ session,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("hashCTX is initialized by internal trusted function")
      /* mcuxClHash_Context_t context:   */ pContext->hashCtx,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
      /* mcuxCl_InputBuffer_t in:        */ pIn,
      /* uint32_t inSize:               */ inLength));
    MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashProcess);

    MCUX_CSSL_DI_EXPUNGE(pIn, pIn);
    MCUX_CSSL_DI_EXPUNGE(inLength, inLength);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHmac_Engine_Update_Sw);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_Engine_Finalize_Sw, mcuxClHmac_FinalizeEngine_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_Engine_Finalize_Sw(
    mcuxClSession_Handle_t session,
    mcuxClHmac_Context_Sw_t * const pContext,
    mcuxCl_Buffer_t pOut,
    uint32_t *const pOutLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_Engine_Finalize_Sw);

    const mcuxClHash_AlgorithmDescriptor_t *hashAlgo = ((mcuxClHmac_ModeDescriptor_t *) (pContext->common.pMode->pCustom))->hashAlgorithm;
    const uint32_t hashSize = hashAlgo->hashSize;
    const uint32_t hashBlockSize = hashAlgo->blockSize;

    /****************************************************************************************************************************************/
    /* Finalize the inner hash by calling Hash-finalize with the Hash context stored in the Hmac context and write the digest to work area  */
    /****************************************************************************************************************************************/

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("hashSize is less than PH_NCCLHASH_BLOCK_SIZE_MAX and hashSize+4-1 is less than MAX of uint32_t")
    uint32_t hashWordSize = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(hashSize);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
    MCUX_CSSL_FP_FUNCTION_CALL(uint32_t*, pInnerHash, mcuxClSession_allocateWords_cpuWa(session, hashWordSize));
    uint32_t hashOutputSize = 0u;

    MCUXCLBUFFER_INIT_RW(pInnerHashOutBuf, session, (uint8_t *)pInnerHash, hashSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish));
    MCUX_CSSL_FP_FUNCTION_CALL(
      resultHashFinish,
      mcuxClHash_finish(session, pContext->hashCtx, pInnerHashOutBuf, &hashOutputSize)
    );
    MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashFinish);

    /**********************************************************************/
    /* Initialize a new Hash context (re-using the old context's memory)  */
    /**********************************************************************/

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init));
    MCUX_CSSL_FP_FUNCTION_CALL(resultHashInit, mcuxClHash_init(session, pContext->hashCtx, hashAlgo));
    MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashInit);

    /***********************************************************************************************************************************/
    /* XOR the opad to the block-sized key that is stored in the Hmac context and Hash-process it (the first block of the outer hash)  */
    /***********************************************************************************************************************************/
    uint8_t *pKeyData = (uint8_t *) pContext->preparedHmacKey;

    /* Balance DI for call to mcuxClMemory_XORWithConst_secure_int */
    MCUX_CSSL_DI_RECORD(memoryXorWithConstCalls, 2u * (uint32_t)pKeyData);
    MCUX_CSSL_DI_RECORD(memoryXorWithConstCalls, hashBlockSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XORWithConst_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XORWithConst_secure_int(pKeyData, pKeyData, MCUXCLMAC_HMAC_OPAD_BYTE, hashBlockSize));

    MCUXCLBUFFER_INIT_RO(pKeyDataBuf, session, pKeyData, hashBlockSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process));
    MCUX_CSSL_FP_FUNCTION_CALL(resultHashProcess, mcuxClHash_process(
      /* mcuxCLSession_Handle_t session: */ session,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("hashCTX is initialized by internal trusted function")
      /* mcuxClHash_Context_t context:   */ pContext->hashCtx,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
      /* mcuxCl_InputBuffer_t in:        */ pKeyDataBuf,
      /* uint32_t inSize:               */ hashBlockSize));
    MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashProcess);

    /********************************************************************************/
    /* Hash-process the digest from before, residing in work area (the inner hash)  */
    /********************************************************************************/

    MCUXCLBUFFER_INIT_RO(pInnerHashInBuf, session, pInnerHash, hashSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process));
    MCUX_CSSL_FP_FUNCTION_CALL(resultHashProcess2, mcuxClHash_process(
      /* mcuxCLSession_Handle_t session: */ session,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("hashCTX is initialized by internal trusted function")
      /* mcuxClHash_Context_t context:   */ pContext->hashCtx,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
      /* mcuxCl_InputBuffer_t in:        */ pInnerHashInBuf,
      /* uint32_t inSize:               */ hashSize));
    MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashProcess2);

    /**********************************************************************************************************************/
    /* Finalize the outer hash by calling Hash-finalize, write the resulting digest to pOut and its length to pOutLength  */
    /**********************************************************************************************************************/

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish));
    MCUX_CSSL_FP_FUNCTION_CALL(resultHashFinish2, mcuxClHash_finish(
      /* mcuxCLSession_Handle_t session: */ session,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_TAINTED_EXPRESSION("hashCTX is initialized by internal trusted function")
      /* mcuxClHash_Context_t context:   */ pContext->hashCtx,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TAINTED_EXPRESSION()
      /* mcuxCl_Buffer_t pOut            */ pOut,
      /* uint32_t *const pOutSize,      */ pOutLength));
    MCUXCLSESSION_CHECK_ERROR_FAULT(session, resultHashFinish2);

    /* SREQI_MAC_18 - Protect the computed length */
    MCUX_CSSL_DI_RECORD(pOutLength, *pOutLength);

    /* SREQI_MAC_18 - Balance pOut parameter after usage */
    MCUX_CSSL_DI_EXPUNGE(pComputedMac, pOut);

    /* Free but don't clean cpuWa as it does not contain sensitive data. Clear context to destroy it. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_OVERFLOWED_TRUNCATED_STATUS_CODE()
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_cleanupOnExit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClHmac_cleanupOnExit(
        session,
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pContext is 32Bit aligned, context structure does not matter for cleanup.")(uint32_t*)
          pContext,
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
        MCUXCLHMAC_CONTEXT_SIZE_SW_IN_WORDS,
        hashWordSize
      )
    );
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OVERFLOWED_TRUNCATED_STATUS_CODE()

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHmac_Engine_Finalize_Sw);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_Engine_Oneshot_Sw, mcuxClHmac_ComputeEngine_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_Engine_Oneshot_Sw(
    mcuxClSession_Handle_t session,
    mcuxClHmac_Context_Sw_t * const pContext,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inLength,
    mcuxCl_Buffer_t pOut,
    uint32_t *const pOutLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_Engine_Oneshot_Sw);

    /* [Design]
    - TODO: In my opinion, we cannot save much when doing Hmac_Oneshot except for the storing of the block-sized key in context.
            We could oneshot the outer hash instead of multipart (with just two parts), but we have a hash context from the
            inner hash anyway, so we can just as well re-use that.
            So it's probably easiest to just call Hmac_Init, Hmac_Update, Hmac_Finalize here.
            Otherwise, here's the slightly optimized design, leaving out the key-storing:

    - Prepare a block-sized key from the key given in the Hmac context (pContext) and store it in work area
      - If keySize > blockSize
        - Hash the key in OneShot
        - Append the digest with (blockSize - digestSize) zero bytes such that it fills one hash block
      - Else just append the key with (blockSize - keySize) zero bytes such that it fills one hash block
    - Initialize a Hash context for multipart
    - XOR the ipad to the block-sized key in the work area and Hash-process it (the first block of the inner hash)
    - Hash-process the input pIn with length inLength using the Hash context
    - Finalize the inner hash by calling Hash-finalize with the Hash context and write the digest to work area
    - Initialize a new Hash context (re-using the old context's memory)
    - XOR ipad^opad (to remove the ipad from before) to the block-sized key in the work area and Hash-process it (the first block of the outer hash)
    - Hash-process the digest from before (the inner hash)
    - Finalize the outer hash by calling Hash-finalize, write the resulting digest to pOut and its length to pOutLength
    */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_Engine_Init_Sw));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHmac_Engine_Init_Sw(session, pContext));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_Engine_Update_Sw));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHmac_Engine_Update_Sw(session, pContext, pIn, inLength));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_Engine_Finalize_Sw));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHmac_Engine_Finalize_Sw(session, pContext, pOut, pOutLength));

    /* SREQI_MAC_18 - Balancing/protection of parameters after usage was already done in Update and Finalize engines */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHmac_Engine_Oneshot_Sw);
}

const mcuxClHmac_AlgorithmDescriptor_t mcuxClHmac_AlgorithmDescriptor_Sw = {
    .engineInit = mcuxClHmac_Engine_Init_Sw,
    .protection_token_engineInit = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_Engine_Init_Sw),
    .engineUpdate = mcuxClHmac_Engine_Update_Sw,
    .protection_token_engineUpdate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_Engine_Update_Sw),
    .engineFinalize = mcuxClHmac_Engine_Finalize_Sw,
    .protection_token_engineFinalize = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_Engine_Finalize_Sw),
    .engineOneshot = mcuxClHmac_Engine_Oneshot_Sw,
    .protection_token_engineOneShot = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_Engine_Oneshot_Sw),
    .addPadding = NULL,
};
