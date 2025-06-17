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

/** @file  mcuxClHmac_Functions.c
 *  @brief Intermediate layer mcuxClHmac functions
 */

#include <mcuxClToolchain.h>
#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClSession.h>
#include <mcuxClHmac.h>
#include <mcuxClMac.h>
#include <mcuxClMemory.h>
#include <mcuxClKey.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClHmac_MemoryConsumption.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClHmac_Internal_Memory.h>
#include <internal/mcuxClHmac_Internal_Functions.h>
#include <internal/mcuxClHmac_Internal_Types.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClMemory_CompareDPASecure_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClCrc_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_castToHmacAlgorithm)
static mcuxClHmac_Algorithm_t mcuxClHmac_castToHmacAlgorithm(void* pAlgorithm)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClHmac_Algorithm_t) pAlgorithm;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_castUint32ToHmacContext)
static mcuxClHmac_Context_Sw_t* mcuxClHmac_castUint32ToHmacContext(uint32_t* pContext)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClHmac_Context_Sw_t* ) pContext;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_castMacContextToHmacContext)
static mcuxClHmac_Context_Sw_t* mcuxClHmac_castMacContextToHmacContext(mcuxClMac_Context_t* pContext)
{
  MCUX_CSSL_ANALYSIS_START_CAST_TO_MORE_SPECIFIC_TYPE()
  return (mcuxClHmac_Context_Sw_t* ) pContext;
  MCUX_CSSL_ANALYSIS_STOP_CAST_TO_MORE_SPECIFIC_TYPE()
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_compute, mcuxClMac_ComputeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClHmac_compute(
    mcuxClSession_Handle_t session,
    mcuxClKey_Handle_t key,
    mcuxClMac_Mode_t mode,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inLength,
    mcuxCl_Buffer_t pMac,
    uint32_t * const pMacLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_compute);

    /* SREQI_MAC_18 - Protect the input parameters. Will be balanced in pAlgo->engineOneshot() */
    MCUX_CSSL_DI_RECORD(pIn, pIn);
    MCUX_CSSL_DI_RECORD(inLength, inLength);
    MCUX_CSSL_DI_RECORD(pMac, pMac);

    mcuxClHmac_Algorithm_t pAlgo = mcuxClHmac_castToHmacAlgorithm(mode->common.pAlgorithm);
    mcuxClHmac_Context_Sw_t *pContext = mcuxClHmac_castUint32ToHmacContext(mcuxClSession_allocateWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLHMAC_INTERNAL_CONTEXT_SIZE)));

    pContext->common.pMode = mode;
    pContext->key = (mcuxClKey_Descriptor_t *) key;
    MCUX_CSSL_FP_EXPECT(pAlgo->protection_token_engineOneShot);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->engineOneshot(session, pContext, pIn, inLength, pMac, pMacLength));

    MCUX_CSSL_DI_EXPUNGE(pMacLength, *pMacLength); /* Was protected in pAlgo->engineOneshot() */
    /* Free pContext and return. No sensitive data remains to be cleared. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_cleanupOnExit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHmac_cleanupOnExit(session, NULL, 0u, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLHMAC_INTERNAL_CONTEXT_SIZE)));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHmac_compute, MCUXCLMAC_STATUS_OK);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_init, mcuxClMac_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_init(
    mcuxClSession_Handle_t session,
    mcuxClMac_Context_t * const pContext,
    mcuxClKey_Handle_t key)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_init);

    mcuxClHmac_Context_Sw_t * const pCtx = mcuxClHmac_castMacContextToHmacContext(pContext);
    mcuxClHmac_Algorithm_t pAlgo = mcuxClHmac_castToHmacAlgorithm(pCtx->common.pMode->common.pAlgorithm);

    pCtx->key = (mcuxClKey_Descriptor_t *) key;
    MCUX_CSSL_FP_EXPECT(pAlgo->protection_token_engineInit);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->engineInit(session, pCtx));

    /* Init context CRC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pCtx, MCUXCLHMAC_INTERNAL_CONTEXT_SIZE));

    /* Nothing to clean, just forward return code. */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHmac_init);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_process, mcuxClMac_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClHmac_process(
    mcuxClSession_Handle_t session,
    mcuxClMac_Context_t * const pContext,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_process);

    /* SREQI_MAC_18 - Protect the input parameters. Will be balanced in pAlgo->engineUpdate() */
    MCUX_CSSL_DI_RECORD(pIn, pIn);
    MCUX_CSSL_DI_RECORD(inLength, inLength);

    mcuxClHmac_Context_Sw_t * const pCtx = mcuxClHmac_castMacContextToHmacContext(pContext);
    mcuxClHmac_Algorithm_t pAlgo = mcuxClHmac_castToHmacAlgorithm(pCtx->common.pMode->common.pAlgorithm);

    /* Check context CRC. Error is handled inside CRC. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pCtx, MCUXCLHMAC_INTERNAL_CONTEXT_SIZE));

    MCUX_CSSL_FP_EXPECT(pAlgo->protection_token_engineUpdate);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->engineUpdate(session, pCtx, pIn, inLength));

    /* Update context CRC */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pCtx, MCUXCLHMAC_INTERNAL_CONTEXT_SIZE));

    /* Nothing to clean, just forward return code. */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHmac_process, MCUXCLMAC_STATUS_OK);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_finish, mcuxClMac_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_finish(
    mcuxClSession_Handle_t session,
    mcuxClMac_Context_t * const pContext,
    mcuxCl_Buffer_t pMac,
    uint32_t * const pMacLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_finish);

    /* SREQI_MAC_18 - Protect the input parameter pMac. Will be balanced in pAlgo->engineFinalize() */
    MCUX_CSSL_DI_RECORD(pMac, pMac);

    mcuxClHmac_Context_Sw_t* const pCtx = mcuxClHmac_castMacContextToHmacContext(pContext);
    mcuxClHmac_Algorithm_t pAlgo = mcuxClHmac_castToHmacAlgorithm(pCtx->common.pMode->common.pAlgorithm);

    /* Check context CRC. Error is handled inside CRC. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pCtx, MCUXCLHMAC_INTERNAL_CONTEXT_SIZE));

    MCUX_CSSL_FP_EXPECT(pAlgo->protection_token_engineFinalize);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->engineFinalize(session, pCtx, pMac, pMacLength));

    MCUX_CSSL_DI_EXPUNGE(pMacLength, *pMacLength); /* Was protected in pAlgo->engineFinalize() */

    /* Nothing to clean, just forward return code. */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHmac_finish);
}


