/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/**
 * @file  mcuxClEcc_ArithmeticOperation_PointSub.c
 * @brief implementation of mcuxClEcc_ArithOp_PointSub function
 */


#include <mcuxClCore_Platform.h>

#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal.h>

#include <internal/mcuxClMath_Internal.h>

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION

/* Arithmetic operation descriptor for point subtraction on Weierstrass curves */
const mcuxClEcc_ArithmeticOperationDescriptor_t mcuxClEcc_ArithOpDesc_PointSub =
{
  .arithOpFct = mcuxClEcc_ArithOp_PointSub,
  .arithOpFct_FP_FuncId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithOp_PointSub)
};


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_ArithOp_PointSub, mcuxClEcc_ArithmeticOperationFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_ArithOp_PointSub(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams,
    mcuxCl_InputBuffer_t pOp1,
    uint32_t op1Size,
    mcuxCl_InputBuffer_t pOp2,
    uint32_t op2Size,
    mcuxCl_Buffer_t pResult,
    uint32_t * const pResultSize
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_ArithOp_PointSub);

    MCUX_CSSL_FP_FUNCTION_CALL(ret_PointAddSubFct,
       mcuxClEcc_ArithOp_PointAddSub(pSession,
                                    pEccWeierDomainParams,
                                    pOp1,
                                    op1Size,
                                    pOp2,
                                    op2Size,
                                    pResult,
                                    pResultSize,
                                    mcuxClEcc_ArithOp_PointSub));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ArithOp_PointSub, ret_PointAddSubFct,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithOp_PointAddSub));
}

#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION */