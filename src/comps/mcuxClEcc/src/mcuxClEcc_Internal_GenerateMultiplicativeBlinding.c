/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @file  mcuxClEcc_Internal_GenerateMultiplicativeBlinding.c
 * @brief mcuxClEcc: implementation of GenerateMultiplicativeBlinding functions
 */


#include <stdint.h>

#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClRandom.h>

#include <mcuxClEcc.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_FUP.h>
#include <internal/mcuxClRandom_Internal_Functions.h>



/**
 * \brief This function securely generates a multiplicative decomposition (sigma, phi)
 * of a secret scalar k with a 64-bit random phi with MSBit set to 1 and
 * sigma = phi^(-1) * k mod n.
 *
 * Inputs:
 *   pSession: handle for the current CL session;
 *   scalarSize: size of the scalar k to be blinded.
 *
 * Returns:
 *  - MCUXCLECC_STATUS_OK            if the function executed successfully
 *  - MCUXCLECC_STATUS_NEUTRAL_POINT if the scalar is zero
 *  - MCUXCLECC_STATUS_RNG_ERROR     random number generation (PRNG) error (unexpected behavior)
 * 
 * Prerequisites:
 *  - The decoded secret scalar k is contained in buffer ECC_S2;
 *  - ps1Len = (operandSize, operandSize).
 *
 * Results:
 *  - the 64-bit blinding phi is contained in buffer ECC_S0;
 *  - the blinded scalar sigma is contained in buffer ECC_S1.
 *  - ECC_V0 points to &pS0[MCUXCLPKC_WORDSIZE]
 *
 * Other modifications:
 *  - buffers ECC_T0, ECC_T1, ECC_T3 are modified (as temp).
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_GenerateMultiplicativeBlinding)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_GenerateMultiplicativeBlinding(mcuxClSession_Handle_t pSession, uint32_t scalarSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_GenerateMultiplicativeBlinding);

    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();

    uint8_t *pS0 = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S0]);
    uint8_t *pS1 = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S1]);
    uint8_t *pS2 = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S2]);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(scalarSize, 0u, 2u * 57u, MCUXCLECC_STATUS_FAULT_ATTACK)
    uint32_t scalarPkcAlignedSize = ((scalarSize + MCUXCLPKC_WORDSIZE - 1u) / MCUXCLPKC_WORDSIZE) * MCUXCLPKC_WORDSIZE;
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(scalarPkcAlignedSize, 0u, 120u, MCUXCLECC_STATUS_FAULT_ATTACK)
    /* Clean bytes on top of the blinding phi to be generated in ECC_S0 considered as buffer of size scalarPkcAlignedSize+pkcWordSize */
    MCUX_CSSL_DI_RECORD(sumOfMemClearParams, &pS0[MCUXCLECC_SCALARBLINDING_BYTELEN]);
    MCUX_CSSL_DI_RECORD(sumOfMemClearParams, scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE - MCUXCLECC_SCALARBLINDING_BYTELEN);
    MCUXCLPKC_WAITFORFINISH();
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(
      &pS0[MCUXCLECC_SCALARBLINDING_BYTELEN],
      scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE - MCUXCLECC_SCALARBLINDING_BYTELEN
    ));

    /* Generate S0 = phi = a 64-bit random, with PRNG. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate_Internal));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_ncGenerate_Internal(pSession, pS0, MCUXCLECC_SCALARBLINDING_BYTELEN));

    /* Set MSBit of phi */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_CONST);
    MCUXCLPKC_FP_CALC_OP1_CONST(ECC_T1, 0u);
    MCUXCLPKC_WAITFORFINISH();
    uint32_t *p32T1 = MCUXCLPKC_OFFSET2PTRWORD(pOperands[ECC_T1]);
    p32T1[1] = 0x80000000u;
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR);
    MCUXCLPKC_FP_CALC_OP1_OR(ECC_S0, ECC_S0, ECC_T1);

    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS2_SETLENGTH(scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE, operandSize);
    /* Calculate T3 = phi*2^(-8*(scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE)) mod n using Montgomery reduction. */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_MC2_MR);
    MCUXCLPKC_FP_CALC_MC2_MR(ECC_T3, ECC_S0, ECC_N);

    /* Calculate T0 = phi^(-1)*2^(8*(scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE)) mod n. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv));
    MCUXCLMATH_FP_MODINV(ECC_T0, ECC_T3, ECC_N, ECC_T1);

    /* Clean garbage bytes of ECC_S1 and ECC_S2 as preparation for the upcoming blinded computations */
    /* NOTE: Since ECC_S1 will later be the target buffer for the blinded sub-private key, this step also serves as a random pre-initialization. */
    MCUX_CSSL_DI_RECORD(sumOfMemClearParams, &pS2[scalarSize]);
    MCUX_CSSL_DI_RECORD(sumOfMemClearParams, scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE - scalarSize);
    MCUXCLPKC_WAITFORFINISH();
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClMemory_clear_int(&pS2[scalarSize], scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE - scalarSize)
    );

    MCUX_CSSL_DI_RECORD(sumOfMemClearParams, &pS1[scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE - 1u]);
    MCUX_CSSL_DI_RECORD(sumOfMemClearParams, 1u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(&pS1[scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE - 1u], 1u));

    /* Generate additive blinding rnd of size scalarPkcAlignedSize+pkcWordSize-1 in buffer ECC_S1 */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate_Internal));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_ncGenerate_Internal(pSession, pS1, scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE - 1u));

    /* Reset PS2 as it was changed by MCUXCLMATH_FP_MODINV */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS2_SETLENGTH(scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE, operandSize);

    pOperands[ECC_V0] = MCUXCLPKC_PTR2OFFSET(&pS0[MCUXCLPKC_WORDSIZE]);
    /* Calculate T3 = phi^-1 * rnd */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_MC2_MM);
    MCUXCLPKC_FP_CALC_MC2_MM(ECC_T3, ECC_S1, ECC_T0, ECC_N);

    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS2_SETLENGTH(0u, scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE);

    /* Calculate S1 = S1 + S2 = s + rnd */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP2_ADD);
    MCUXCLPKC_FP_CALC_OP2_ADD(ECC_S1, ECC_S1, ECC_S2);

    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS2_SETLENGTH(scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE, operandSize);

    /* Calculate sigma = s*phi^-1 mod n */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_GenerateMultiplicativeBlinding, mcuxClEcc_FUP_GenerateMultiplicativeBlinding_LEN);

    /* Read zero flag to check if sigma is zero and return MCUXCLECC_STATUS_NEUTRAL_POINT if sigma (and respectively k mod n) is zero. */
    uint32_t zeroFlag = MCUXCLPKC_WAITFORFINISH_GETZERO();
    if (MCUXCLPKC_FLAG_ZERO == zeroFlag)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_GenerateMultiplicativeBlinding, MCUXCLECC_STATUS_NEUTRAL_POINT);
    }


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_GenerateMultiplicativeBlinding, MCUXCLECC_STATUS_OK);
}
