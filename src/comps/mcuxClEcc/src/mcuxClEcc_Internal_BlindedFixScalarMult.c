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
 * @file  mcuxClEcc_Internal_BlindedFixScalarMult.c
 * @brief Generic ECC implementation of multiplicatively blinded scalar multiplication with fixed base point
 */


#include <mcuxClSession.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClMath_Internal_Utils.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_UPTRT_access.h>

#include <internal/mcuxClSession_Internal_EntryExit.h>


/**
 * This function implements the scalar multiplication k*G for a secret scalar k in {0,...,n-1}
 * and the base point G of order n on the given curve. If the scalar k is zero, the function
 * returns MCUXCLECC_STATUS_NEUTRAL_POINT. If it is not zero, the function generates a blinded
 * multiplicative splitting (phi,sigma) of the scalar k with a 64 bit blinding with MSBit set to 1
 * and sigma = k*phi^(-1) mod n, and performs two secure scalar multiplications,
 * the first with the blinded scalar sigma and the second with the blinding phi.
 *
 * Input:
 *  - pSession          Handle for the current CL session
 *  - pDomainParameters Pointer to common domain parameters
 *
 * Return values:
 *  - MCUXCLECC_STATUS_OK            if the function executed successfully
 *  - MCUXCLECC_STATUS_NEUTRAL_POINT if the scalar is zero
 *  - MCUXCLECC_STATUS_RNG_ERROR     random number generation (PRNG) error (unexpected behavior)
 *  - MCUXCLECC_STATUS_FAULT_ATTACK  fault attack (unexpected behavior) is detected
 *
 * Prerequisites:
 *  - The secret scalar k is contained in buffer ECC_S2
 *  - ps1Len = (operandSize, operandSize)
 *  - Buffers ECC_CP0 and ECC_CP1 contain the curve parameters a and d in MR
 *  - Buffer ECC_PFULL contains p'||p
 *  - Buffer ECC_NFULL contains n'||n
 *  - Buffers ECC_PS and ECC_NS contain the shifted moduli associated to p and n
 *
 * Result:
 *  If MCUXCLECC_STATUS_OK is returned:
 *  - the result k*G is stored in curve dependent coordinates in buffers ECC_COORD00, ECC_COORD01,....
 *  - the blinding phi concatenated with the blinded scalar sigma in buffer ECC_S0 (considering buffer size operandSize + MCUXCLPKC_WORDSIZE)
 *
 * @attention The PKC calculation might be still on-going, call #MCUXCLPKC_WAITFORFINISH before CPU accesses to the result.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_BlindedFixScalarMult)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_BlindedFixScalarMult(mcuxClSession_Handle_t pSession,
                                                                         mcuxClEcc_CommonDomainParams_t *pCommonDomainParams, uint32_t scalarLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_BlindedFixScalarMult);

    /*
     * Step 1: Securely generate a multiplicative decomposition (sigma,phi) of k with a 64 bit random phi
     *         with MSBit and LSBit set to 1 stored in ECC_S0 and sigma = phi^(-1)*k mod n stored in ECC_S1
     *         by calling function mcuxClEcc_GenerateMultiplicativeBlinding.
     */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_GenMulBlind,
        mcuxClEcc_GenerateMultiplicativeBlinding(pSession, scalarLength));
    if (MCUXCLECC_STATUS_OK != ret_GenMulBlind)
    {
        /* GenerateMultiplicativeBlinding is returning only OK, NEUTRAL_POINT or RNG_ERROR */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_BlindedFixScalarMult, ret_GenMulBlind);
    }

    /*
     * Step 2: Call pDomainParameters->pSecFixScalarMultFct to securely calculate the scalar multiplication sigma*G
     *         and store the result P' in curve dependent coordinates in MR in buffers ECC_COORD00, ECC_COORD01,....
     */
    /* Copy of blinded scalar sigma = phi^-1*k to ECC_V0, which points to &pS0[MCUXCLPKC_WORDSIZE]*/
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_V0, ECC_S1, 0u);

    MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();
    uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    MCUX_CSSL_FP_FUNCTION_CALL(leadingZerosN, mcuxClMath_LeadingZeros(ECC_N));
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("The result does not wrap. The leadingZerosN is less than operandSize * 8u.")
    uint32_t bitLenN = (operandSize * 8u) - leadingZerosN;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    MCUX_CSSL_DI_RECORD(secureFixScalarMult, MCUXCLECC_SCALARMULT_OPTION_SECURE * bitLenN);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        pCommonDomainParams->pScalarMultFunctions->secFixScalarMultFct(
            pSession,
            pCommonDomainParams,
            ECC_S1,
            bitLenN,
            MCUXCLECC_SCALARMULT_OPTION_AFFINE_INPUT |
            MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_OUTPUT |
            MCUXCLECC_SCALARMULT_OPTION_NO_OUTPUT_VALIDATION));

    /*
     * Step 3: Call pDomainParameters->pSecVarScalarMultFct to securely calculate the scalar multiplication phi*P',
     *         store the result P in curve dependent coordinates in MR in buffers ECC_COORD00, ECC_COORD01,...,
     *         and verify that the point lies on the curve.
     */
    MCUX_CSSL_DI_RECORD(secureVarScalarMult, MCUXCLECC_SCALARMULT_OPTION_SECURE * MCUXCLECC_SCALARBLINDING_BITSIZE);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        pCommonDomainParams->pScalarMultFunctions->secVarScalarMultFct(
            pSession,
            pCommonDomainParams,
            ECC_S0,
            MCUXCLECC_SCALARBLINDING_BITSIZE,
            MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_INPUT |
            MCUXCLECC_SCALARMULT_OPTION_AFFINE_OUTPUT |
            MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_BlindedFixScalarMult, MCUXCLECC_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_GenerateMultiplicativeBlinding),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_LeadingZeros),
        pCommonDomainParams->pScalarMultFunctions->secFixScalarMultFctFPId,
        pCommonDomainParams->pScalarMultFunctions->secVarScalarMultFctFPId);
}
