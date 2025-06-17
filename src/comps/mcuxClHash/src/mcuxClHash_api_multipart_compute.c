/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

#include <mcuxClHash.h>
#include <internal/mcuxClHash_Internal.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslSecureCounter_Cfg.h>

#include <internal/mcuxClSession_Internal_EntryExit.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_finish_internal)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHash_finish_internal(
    mcuxClSession_Handle_t session,
    mcuxClHash_Context_t pContext,
    mcuxCl_Buffer_t pOut,
    uint32_t *const pOutSize
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_finish_internal);

    if((NULL == pContext->algo) || (NULL == pContext->algo->finishSkeleton))
    {
        MCUXCLSESSION_ERROR(session, MCUXCLHASH_STATUS_INVALID_PARAMS);
    }

    MCUX_CSSL_FP_EXPECT(pContext->algo->protection_token_finishSkeleton);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pContext->algo->finishSkeleton(session, pContext, pOut, pOutSize));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHash_finish_internal);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_finish)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHash_finish(
    mcuxClSession_Handle_t session,
    mcuxClHash_Context_t pContext,
    mcuxCl_Buffer_t pOut,
    uint32_t *const pOutSize
    )
{
    MCUXCLSESSION_ENTRY(session, mcuxClHash_finish, diRefValue, MCUXCLHASH_STATUS_FAULT_ATTACK);

    /* DI balancing of finishSkeleton */
    MCUX_CSSL_DI_RECORD(finishSkeletonParams, pContext);
    MCUX_CSSL_DI_RECORD(finishSkeletonParams, pOut);
    MCUX_CSSL_DI_RECORD(finishSkeletonParams, pOutSize);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish_internal));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHash_finish_internal(session, pContext, pOut, pOutSize));

    MCUXCLSESSION_EXIT(session,
        mcuxClHash_finish,
        diRefValue,
        MCUXCLHASH_STATUS_OK,
        MCUXCLHASH_STATUS_FAULT_ATTACK
        );
}
