/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

/**
 * @file  mcuxClEcc_TwEd_Internal_SecureVarScalarMult.c
 * @brief Secure scalar multiplication with a variable point P on a twisted Edwards curve
 */

#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClEcc.h>
#include <internal/mcuxClEcc_TwEd_Internal.h>
#include <internal/mcuxClSession_Internal.h>

/**
 * Function that performs a secure scalar multiplication with a variable point P on a twisted Edwards curve, protected against SCA.
 * This function is a wrapper to mcuxClEcc_TwEd_VarScalarMult.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_TwEd_SecureVarScalarMult, mcuxClEcc_ScalarMultFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_TwEd_SecureVarScalarMult(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_CommonDomainParams_t *pDomainParams,
    uint8_t iScalar,
    uint32_t scalarBitLength,
    uint32_t options
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_TwEd_SecureVarScalarMult);

    options |= MCUXCLECC_SCALARMULT_OPTION_SECURE;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_TwEd_VarScalarMult));
    MCUX_CSSL_FP_FUNCTION_CALL(returnScalarMult,
        mcuxClEcc_TwEd_VarScalarMult(pSession, pDomainParams, iScalar, scalarBitLength, options));

    if(MCUXCLECC_STATUS_OK != returnScalarMult)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_TwEd_SecureVarScalarMult);
}
