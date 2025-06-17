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

/**
 * @file  mcuxClEcc_TwEd_Internal_PlainFixScalarMult25519.c
 * @brief Plain scalar multiplication with (fixed) base point for twisted Edwards curve Ed25519
 */


#include <mcuxClCore_Platform.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClEcc_TwEd_Internal.h>

#include <internal/mcuxClSession_Internal.h>

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_TwEd_PlainFixScalarMult25519, mcuxClEcc_ScalarMultFunction_t)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_TwEd_PlainFixScalarMult25519(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
    mcuxClSession_Handle_t pSession,                 ///<  [in]  pSession            Handle for the current CL session
    mcuxClEcc_CommonDomainParams_t *pDomainParams,   ///<  [in]  pDomainParams       Pointer to ECC common domain parameters structure
    uint8_t iScalar,                                ///<  [in]  iScalar             Pointer table index of scalar
    uint32_t scalarBitLength,                       ///<  [in]  scalarBitLength     Bit length of the scalar; must be a multiple of 4
    uint32_t options                                ///<  [in]  options             Parameter to pass options
)
{
    (void) pSession;
    options |= MCUXCLECC_SCALARMULT_OPTION_PLAIN;

    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_TwEd_PlainFixScalarMult25519);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_TwEd_FixScalarMult));
    MCUX_CSSL_FP_FUNCTION_CALL(returnScalarMult, mcuxClEcc_TwEd_FixScalarMult(pSession,
            pDomainParams,
            iScalar,
            scalarBitLength,
            mcuxClEcc_TwEd_MixedPointAddEd25519,
            mcuxClEcc_TwEd_PointDoubleEd25519,
            options
        )
    );

    if(MCUXCLECC_STATUS_OK != returnScalarMult)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_TwEd_PlainFixScalarMult25519);
}
