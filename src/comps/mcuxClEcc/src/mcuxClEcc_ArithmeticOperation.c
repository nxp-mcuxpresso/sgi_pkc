/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @file  mcuxClEcc_ArithmeticOperation.c
 * @brief implementation of mcuxClEcc_ArithmeticOperation functions
 */

#include <mcuxClCore_Platform.h>

#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClEcc.h>
#include <internal/mcuxClEcc_Internal.h>

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_ArithmeticOperation)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_ArithmeticOperation(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_ArithmeticOperation_t arithmeticOperation,
    mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams,
    mcuxCl_InputBuffer_t pOp1,
    uint32_t op1Size,
    mcuxCl_InputBuffer_t pOp2,
    uint32_t op2Size,
    mcuxCl_Buffer_t pResult,
    uint32_t * const pResultSize )
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClEcc_ArithmeticOperation, diRefValue, MCUXCLECC_STATUS_FAULT_ATTACK);

    /* Record input pointers and length to arithOpFct*/
    MCUX_CSSL_DI_RECORD(arithOpFct, (uint32_t)(pOp1) + op1Size + (uint32_t)(pOp2) + op2Size + (uint32_t)(pResult));
    MCUX_CSSL_FP_FUNCTION_CALL(ret_ArithOpFct,
        arithmeticOperation->arithOpFct(pSession,
                                        pEccWeierDomainParams,
                                        pOp1,
                                        op1Size,
                                        pOp2,
                                        op2Size,
                                        pResult,
                                        pResultSize));

    MCUXCLSESSION_EXIT(pSession, mcuxClEcc_ArithmeticOperation, diRefValue, ret_ArithOpFct, MCUXCLECC_STATUS_FAULT_ATTACK, arithmeticOperation->arithOpFct_FP_FuncId);
}

#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION */