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
 * @file  mcuxClEcc_EdDSA_Internal_DecodePoint_Ed25519.c
 * @brief Function to decode a point
 */


#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClBuffer.h>
#include <mcuxClEcc.h>

#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal_Hash.h>
#include <internal/mcuxClEcc_EdDSA_Internal_FUP.h>


/**
 * This function decodes an encoded point Penc on Ed25519 and converts it to homogeneous coordinates
 * (x:y:1) in MR. It also verifies that the resulting point lies on the curve Ed25519.
 *
 * Input:
 *  - pDomainParams Pointer to ECC common domain parameters for Ed25519
 *  - pEncPoint Buffer for encoded point
 *
 * Prerequisites:
 * - ps1Len = (operandSize, operandSize)
 * - Buffers ECC_CP0 and ECC_CP1 contain the curve parameters a and d in MR
 * - Buffer ECC_PFULL contains p'||p
 * - Buffer ECC_P contains modulus p in NR
 * - Buffer ECC_PS contains the shifted modulus associated to p
 * - Buffer ECC_COORD00 contains the encoded point Penc
 *
 * Result:
 *  - Buffers ECC_COORD00, ECC_COORD01, ECC_COORD02 contain the homogeneous coordinates (x:y:1) in MR
 *
 * Return values:
 *  - MCUXCLECC_STATUS_OK                if the function executed successfully
 *  - MCUXCLECC_STATUS_INVALID_PARAMS    if the input point is invalid, i.e. the decoding failed
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_DecodePoint_Ed25519, mcuxClEcc_EdDSA_DecodePointFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_EdDSA_DecodePoint_Ed25519(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_EdDSA_DomainParams_t *pDomainParams
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_DecodePoint_Ed25519);

    /* DI protect the byte length of the exponent.
     * Will be balanced in the call to mcuxClMath_ModExp_SqrMultL2R() in Step 5. */
    MCUX_CSSL_DI_RECORD(DecodePoint_ModExp, pDomainParams->common.byteLenP);

    /* Step 1: Read and backup the LSBit x0 from buffer ECC_COORD00 and clear it in buffer ECC_COORD00. */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    const uint32_t encodedLen = (uint32_t) pDomainParams->b / 8u;
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(encodedLen, 1u, (uint32_t) pDomainParams->b / 8u, MCUXCLECC_STATUS_FAULT_ATTACK)
    uint8_t *pEncPointLastByte = &MCUXCLPKC_OFFSET2PTR(pOperands[ECC_COORD00])[encodedLen - 1u];
    uint8_t x0 = (*pEncPointLastByte) >> 7u;
    *pEncPointLastByte &= 0x7Fu;

    /* Step 2: Compute ECC_COORD00 - ECC_P. If the CARRY flag is not set, the decoding failed
    and #MCUXCLECC_STATUS_INVALID_PARAMS is returned. */
    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_COORD00, ECC_P);
    if (MCUXCLPKC_FLAG_CARRY != MCUXCLPKC_WAITFORFINISH_GETCARRY())
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);                   /* Step 3 */
    }

    /* Step 3: Import pDomainParams->pSqrtMinusOne to buffer ECC_COORD04. */
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(ECC_COORD04, pDomainParams->pSqrtMinusOne, pDomainParams->common.byteLenP, operandSize);

    /* Step 4: Set u = y^2-1 and v = d*y^2 + 1 and perform the following steps to compute the x-coordinate candidate x':
     *  - Set x~ = u*v^3 * (u*v^7)^((p-5)/8) mod p
     *  - If v * x~^2 = -u mod p, set x' = x~ * 2^((p-1)/4) mod p.
     *  - If v * x~^2 =  u mod p, set x' = x~.
     *  - If v * x~^2 != +/- u mod p, the decoding failed. */

    /* Compute (u * v^7)^((p-5)/8) mod p and the Y-, and Z-coordinate for the point decoding result (X:Y:Z) */
    uint32_t *pC3 = MCUXCLPKC_OFFSET2PTRWORD(pOperands[ECC_COORD03]);
    /* DI protect pExp param for call to MCUXCLMATH_FP_MODEXP_SQRMULTL2R */
    MCUX_CSSL_DI_RECORD(protectExpPointer, pC3);
    pOperands[ECC_V0] = (uint16_t) 3u;
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_EdDSA_Internal_DecodePoint_PrepareExp_Common,
                        mcuxClEcc_FUP_EdDSA_Internal_DecodePoint_PrepareExp_Common_LEN);
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_EdDSA_Internal_DecodePoint_PrepareExp_Ed25519,
                        mcuxClEcc_FUP_EdDSA_Internal_DecodePoint_PrepareExp_Ed25519_LEN);
    MCUXCLPKC_WAITFORFINISH(); // Needed to ensure that the first of the two FUP programs is finished before the subsequent endianness switch

    MCUXCLPKC_FP_SWITCHENDIANNESS(pC3, pDomainParams->common.byteLenP); // the exponent should be in big endian format for MCUXCLMATH_FP_MODEXP_SQRMULTL2R
    MCUXCLMATH_FP_MODEXP_SQRMULTL2R((const uint8_t*)pC3, (uint32_t) pDomainParams->common.byteLenP, ECC_COORD00, ECC_T3, ECC_P, TWED_PP_Y0); // ECC_COORD00 = (u * v^7)^((p-5)/8) mod p; use TWED_PP_Y0 as temp buffer

    /* Compute the x~ candidate, x~^2 * v + u, and the square root of -1 mod p */
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_EdDSA_Internal_DecodePoint_ComputeXCandidate_Ed25519,
                        mcuxClEcc_FUP_EdDSA_Internal_DecodePoint_ComputeXCandidate_Ed25519_LEN);
    uint32_t zeroFlag_check1 = MCUXCLPKC_WAITFORFINISH_GETZERO();            // If flag is set, x~^2 * v = -u mod p

    /* Calculate value x' */
    MCUX_CSSL_FP_BRANCH_DECL(vx2IsMinusU);
    if (MCUXCLPKC_FLAG_ZERO == zeroFlag_check1)
    {
        /* If x~^2 * v == -u, set x' = x~ * 2^((p-1)/4) */
        MCUXCLPKC_FP_CALC_MC1_MM(ECC_COORD00, ECC_T3, ECC_T1, ECC_P);        // = x~ * 2^((p-1)/4) = x' in MR
        MCUXCLPKC_FP_CALC_MC1_MS(ECC_COORD00, ECC_COORD00, ECC_P, ECC_P);
        MCUXCLPKC_FP_CALC_MC1_MS(ECC_COORD00, ECC_COORD00, ECC_P, ECC_P);    // x' in MR in range [0,p-1] because 2^256-1 < 3*p

        MCUX_CSSL_FP_BRANCH_POSITIVE(vx2IsMinusU, MCUXCLPKC_FP_CALLED_CALC_MC1_MM,
                                                 MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
                                                 MCUXCLPKC_FP_CALLED_CALC_MC1_MS);
    }
    else
    {
        MCUXCLPKC_FP_CALC_MC1_MS(ECC_T2, ECC_T2, ECC_T0, ECC_P);             // = x~^2 * v + u - u in MR
        MCUXCLPKC_FP_CALC_MC1_MS(ECC_T2, ECC_T2, ECC_T0, ECC_P);             // = x~^2 * v - u in MR in range [0,p-1]
        if (MCUXCLPKC_FLAG_ZERO != MCUXCLPKC_WAITFORFINISH_GETZERO())
        {
            /* If x~^2 * v != +/- u, decoding fails */
            MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
        }
        /* Set x' = x~ */
        MCUXCLPKC_FP_CALC_MC1_MS(ECC_COORD00, ECC_T3, ECC_P, ECC_P);
        MCUXCLPKC_FP_CALC_MC1_MS(ECC_COORD00, ECC_COORD00, ECC_P, ECC_P);    // x' in MR in range [0,p-1] because 2^256-1 < 3*p

        MCUX_CSSL_FP_BRANCH_NEGATIVE(vx2IsMinusU, MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
                                                 MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
                                                 MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
                                                 MCUXCLPKC_FP_CALLED_CALC_MC1_MS);
    }
    /* After this, we have x' in ECC_COORD00 in MR in range [0,p-1], y in MR in ECC_COORD01, 1 in MR in ECC_COORD02, and PKC_ZERO is set if and only if x' = 0 */

    /* Step 5: If the ZERO flag of the PKC is set and x0=1, return #MCUXCLECC_STATUS_INVALID_PARAMS, decoding failed. */
    if ((MCUXCLPKC_FLAG_ZERO == MCUXCLPKC_WAITFORFINISH_GETZERO()) && (1u == x0))
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
    }

    /* Step 6: If x0!=x' mod 2, set ECC_COORD00 = ECC_P - ECC_COORD00. Finally ECC_COORD00 contains x in MR. */
    MCUXCLPKC_FP_CALC_MC1_MR(ECC_T3, ECC_COORD00, ECC_P);                    // x' mod p in NR in range [0,p-1] because ECC_COORD00 is in range [0,p-1]

    uint32_t *pT3FirstWord = MCUXCLPKC_OFFSET2PTRWORD(pOperands[ECC_T3]);    // Loading a word is usually cheaper than loading a byte
    MCUXCLPKC_WAITFORFINISH();
    uint8_t x0_candidate = (uint8_t)(((*pT3FirstWord) & 0x01u) & 0xFFu);                // LSBit of x~

    /* Check if x0 != x' mod 2 */
    MCUX_CSSL_FP_BRANCH_DECL(x0Isx);
    if (x0 != x0_candidate)
    {
        MCUXCLPKC_FP_CALC_OP1_SUB(ECC_COORD00, ECC_P, ECC_COORD00);

        MCUX_CSSL_FP_BRANCH_POSITIVE(x0Isx, MCUXCLPKC_FP_CALLED_CALC_OP1_SUB);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_DecodePoint_Ed25519, MCUXCLECC_STATUS_OK,
        /* Step 2 */
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
        /* Step 3 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),
        /* Step 4 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SwitchEndianness),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModExp_SqrMultL2R),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
        MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(vx2IsMinusU, MCUXCLPKC_FLAG_ZERO == zeroFlag_check1),
        MCUX_CSSL_FP_BRANCH_TAKEN_NEGATIVE(vx2IsMinusU, MCUXCLPKC_FLAG_ZERO != zeroFlag_check1),
        /* Step 6 */
        MCUXCLPKC_FP_CALLED_CALC_MC1_MR,
        MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(x0Isx, x0 != x0_candidate) );
}
