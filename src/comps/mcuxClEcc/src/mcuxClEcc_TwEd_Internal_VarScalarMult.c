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
 * @file  mcuxClEcc_TwEd_Internal_VarScalarMult.c
 * @brief Scalar multiplication with a variable point P on a twisted Edwards curve
 */

#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_Macros.h>

#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClPrng_Internal.h>

#include <mcuxClEcc.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_FUP.h>
#include <internal/mcuxClEcc_TwEd_Internal.h>
#include <internal/mcuxClEcc_TwEd_Internal_FUP.h>

/**
 * Function that performs a scalar multiplication with a variable point P on a twisted Edwards curve, protected against SCA if set SECURE flag in options
 * The input point for this function is assumed to be a valid point on the curve.
 * Therefore, if the option to validate the output is chosen, the function will return FAULT_ATTACK if the output point validation fails.
 *
 * Prerequisites:
 *   -  Buffer buf(iScalar) contains the secret scalar lambda of bit length scalarBitLength
 *   -  Buffers TWED_X, TWED_Y and TWED_Z contain the homogeneous coordinates (X:Y:Z) of P in MR
 *   -  Buffer ECC_CP1 contains d in MR
 *   -  ps1Len = (operandSize, operandSize)
 *   -  Buffer ECC_PFULL contains p'||p
 *   -  Buffer ECC_PS contains the shifted modulus associated to p
 *
 * Result:
 *  - Buffers TWED_X, TWED_Y and TWED_Z contain Xres, Yres and Zres in MR
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_TwEd_VarScalarMult)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_TwEd_VarScalarMult(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_CommonDomainParams_t *pDomainParams,
    uint8_t iScalar,
    uint32_t scalarBitLength,
    uint32_t options
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_TwEd_VarScalarMult);

    /* Determine pointer table pointer */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();  // avoid CPU accessing to PKC workarea when PKC is busy - TODO CLNS-6410: check if this is necessary
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("MISRA Ex. 9 to Rule 11.3 - PKC word is CPU word aligned.")
    const uint32_t *pScalar = (const uint32_t *) MCUXCLPKC_OFFSET2PTR(pOperands[iScalar]);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

    /* Step 1: Initialize the accumulated points in YZ-coordinates
     * Only when MCUXCLECC_SCALARMULT_OPTION_SECURE is enabled in options,
     * - Shuffle the accumulated ladder points' buffers
     * - Generate a random Z-coordinate in [1,p-1] in MR in ECC_T0 and use it to randomize the input point as well as the accumulated point coordinates
     */
    if (MCUXCLECC_SCALARMULT_OPTION_SECURE == (MCUXCLECC_SCALARMULT_OPTION_SECURE_MASK & options))
    {
        MCUXCLPKC_WAITFORFINISH();
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_RandomizeUPTRT));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_RandomizeUPTRT(&pOperands[TWED_ML_Y1], (TWED_ML_Z2 - TWED_ML_Y1 + 1u)));

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_GenerateRandomModModulus));
        MCUX_CSSL_FP_FUNCTION_CALL(ret_GetRandom, mcuxClEcc_GenerateRandomModModulus(pSession, ECC_P, ECC_T0));

        if (MCUXCLECC_STATUS_OK != ret_GetRandom)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_TwEd_VarScalarMult, ret_GetRandom);
        }

        /* Re-randomize the accumulated point's coordinates */
        MCUXCLPKC_WAITFORREADY();
        pOperands[TWED_V0] = pOperands[TWED_X];
        pOperands[TWED_V1] = pOperands[TWED_Y];
        pOperands[TWED_V2] = pOperands[TWED_T];
        pOperands[TWED_V3] = pOperands[TWED_Z];
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_TwEd_UpdateExtHomCoords, mcuxClEcc_FUP_TwEd_UpdateExtHomCoords_LEN);
    }

    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(TWED_ML_Y1, TWED_Z, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(TWED_ML_Z1, TWED_Z, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(TWED_ML_Y2, TWED_Y, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(TWED_ML_Z2, TWED_Z, 0u);

    /* Step 2: Import ladder constant (a/d mod p), convert it to MR modulo p, and store it in buffer ECC_CP0. */
    MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();  // avoid CPU accessing to PKC workarea when PKC is busy
    uint32_t byteLenP = (uint32_t) pDomainParams->byteLenP;
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc));
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(ECC_T0, pDomainParams->pLadderConst, byteLenP, operandSize);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_MC1_MM);
    MCUXCLPKC_FP_CALC_MC1_MM(ECC_CP0, ECC_T0, ECC_PQSQR, ECC_P);

    MCUX_CSSL_ANALYSIS_START_PATTERN_URL_IN_COMMENTS()
    /* Step 3: Perform ladder loop to calculate YZ-coordinates for the resulting point according to Algorithms 4 and 5 in https://ieeexplore.ieee.org/document/6550581
     * For the pointer selection, the function specified by ptrSelectFct is used.
     */
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_URL_IN_COMMENTS()
    uint32_t i = scalarBitLength;
    uint32_t currentScalarWordMask = MCUXCLECC_RANDOM_WORD;
    uint32_t currentScalarWord = 0u;
    uint32_t maskedCurrentScalarWord = 0u;
    //MCUX_CSSL_FP_LOOP_DECL(whileLoop);  TODO: hardening CLNS-16864
    //MCUX_CSSL_FP_BRANCH_DECL(ifInWhile);
    while(0u < i)
    {
        /* Update loop counter, deviation from the design to let iterate over unsigned value */
        --i;

        /* Select pointers pOperands[TWED_VY1],...,pOperands[TWED_VZ2] according to the bit to be processed */
        uint32_t currentScalarBitInWord = i % 32u;
        if((i == (scalarBitLength - 1u)) || ((i % 32u) == 31u))
        {
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word));
            MCUX_CSSL_FP_FUNCTION_CALL(prngGenerateWordRet, mcuxClPrng_generate_word());
            currentScalarWordMask = prngGenerateWordRet;
            MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();  // avoid CPU accessing to PKC workarea when PKC is busy
            uint32_t currentScalarWordIndex = i / 32u;
            currentScalarWord = pScalar[currentScalarWordIndex];
            maskedCurrentScalarWord = currentScalarWord ^ currentScalarWordMask;
            //MCUX_CSSL_FP_BRANCH_POSITIVE(ifInWhile);
        }

        if (MCUXCLECC_SCALARMULT_OPTION_SECURE == (MCUXCLECC_SCALARMULT_OPTION_SECURE_MASK & options))
        {
            MCUX_CSSL_DI_EXPUNGE(varScalarMult, MCUXCLECC_SCALARMULT_OPTION_SECURE);
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_SecurePointSelectML));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_SecurePointSelectML(maskedCurrentScalarWord, currentScalarWordMask, currentScalarBitInWord, TWED_ML_Y1, TWED_VY1));
        }
        else if (MCUXCLECC_SCALARMULT_OPTION_PLAIN == (MCUXCLECC_SCALARMULT_OPTION_SECURE_MASK & options))
        {
            MCUX_CSSL_DI_EXPUNGE(varScalarMult, MCUXCLECC_SCALARMULT_OPTION_PLAIN);
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_TwEd_PlainPtrSelectML));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_TwEd_PlainPtrSelectML(pSession, currentScalarWord, (uint8_t)currentScalarBitInWord));
        }
        else
        {
            MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
        }

        /* Perform the ladder step to calculate (VY2:VZ2) = (VY1:VZ1) + (VY2:VZ2) and (VY1:VZ1) = 2*(VY1:VZ1) */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_VarScalarMult_YZMontLadder_LadderStep, mcuxClEcc_FUP_VarScalarMult_YZMontLadder_LadderStep_LEN);

        /*
         * Shuffle the accumulated points' buffers and re-randomize the coordinates
         * if the number of remaining iterations is a multiple of 8.
         */
        if ((MCUXCLECC_SCALARMULT_OPTION_SECURE == (MCUXCLECC_SCALARMULT_OPTION_SECURE_MASK & options))
                && ((0u < i) && (0u == (i & (MCUXCLECC_TWED_VARSCALARMULT_POINT_RANDOMIZE_PER_BITS - 1u)))))
        {
            /* Re-randomize the accumulated points' coordinates */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_GenerateRandomModModulus));
            MCUX_CSSL_FP_FUNCTION_CALL(ret_GetRandom1, mcuxClEcc_GenerateRandomModModulus(pSession, ECC_P, ECC_T0));
            if (MCUXCLECC_STATUS_OK != ret_GetRandom1)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_TwEd_SecFixScalarMult, ret_GetRandom1);
            }
            MCUXCLPKC_WAITFORREADY();
            pOperands[TWED_V1] = pOperands[TWED_ML_Y1];
            pOperands[TWED_V3] = pOperands[TWED_ML_Z1];
            MCUXCLPKC_FP_CALCFUP_OFFSET(mcuxClEcc_FUP_TwEd_UpdateExtHomCoords, mcuxClEcc_FUP_TwEd_UpdateExtHomCoords_XT_LEN, mcuxClEcc_FUP_TwEd_UpdateExtHomCoords_YZ_LEN);
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));

            MCUXCLPKC_WAITFORREADY();
            pOperands[TWED_V1] = pOperands[TWED_ML_Y2];
            pOperands[TWED_V3] = pOperands[TWED_ML_Z2];
            MCUXCLPKC_FP_CALCFUP_OFFSET(mcuxClEcc_FUP_TwEd_UpdateExtHomCoords, mcuxClEcc_FUP_TwEd_UpdateExtHomCoords_XT_LEN, mcuxClEcc_FUP_TwEd_UpdateExtHomCoords_YZ_LEN);
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));

            /* Shuffle the accumulated points' buffers */
            MCUXCLPKC_WAITFORFINISH();
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ReRandomizeUPTRT));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_ReRandomizeUPTRT(&pOperands[TWED_ML_Y1],
                                                                (uint16_t)operandSize,
                                                                (TWED_ML_Z2 - TWED_ML_Y1 + 1u)));
        }
        /* FP balancing for the loop iteration */
        //MCUX_CSSL_FP_LOOP_ITERATION(whileLoop
            //MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(ifInWhile, (i == (scalarBitLength - 1u)) || ((i % 32u) == 31u)),
            //ptrSelectFctFPId,
            //MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup)
            //);
    }

    /* Step 4: Import curve parameter a, convert it to MR modulo p, and store it in buffer ECC_CP0. */
    MCUXCLPKC_WAITFORFINISH();
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc));
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(ECC_T0, pDomainParams->pCurveParam1, byteLenP, operandSize);
    MCUXCLPKC_FP_CALC_MC1_MM(ECC_CP0, ECC_T0, ECC_PQSQR, ECC_P);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_MC1_MM);

    /* Step 5: Recover the missing X-coordinate */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_VarScalarMult_Recover_X_Coordinate, mcuxClEcc_FUP_VarScalarMult_Recover_X_Coordinate_LEN);

    /* Step 6: If requested,
     *            - convert the result to affine coordinates in NR
     *            - validate the resulting point. */
    if(MCUXCLECC_SCALARMULT_OPTION_AFFINE_OUTPUT == (MCUXCLECC_SCALARMULT_OPTION_OUTPUT_MASK & options))
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv));
        MCUXCLMATH_FP_MODINV(ECC_T0, TWED_Z, ECC_P, ECC_T1);         /* T0 = Z^(-1)*R^(-1) mod p    */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_ConvertHomToAffine, mcuxClEcc_FUP_ConvertHomToAffine_LEN);

        if(MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION == (MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION_MASK & options))
        {
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
            MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_TwEd_PointValidation_AffineNR, mcuxClEcc_FUP_TwEd_PointValidation_AffineNR_LEN);
            if (MCUXCLPKC_FLAG_ZERO != MCUXCLPKC_WAITFORFINISH_GETZERO())
            {
                MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
            }
        }
        else if(MCUXCLECC_SCALARMULT_OPTION_NO_OUTPUT_VALIDATION != (MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION_MASK & options))
        {
            MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
        }
        else
        {
            /* Do nothing */
        }
    }
    else if(MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_OUTPUT != (MCUXCLECC_SCALARMULT_OPTION_OUTPUT_MASK & options))
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }
    else
    {
        if(MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION == (MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION_MASK & options))
        {
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
            MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_TwEd_PointValidation_HomMR, mcuxClEcc_FUP_TwEd_PointValidation_HomMR_LEN);
            if (MCUXCLPKC_FLAG_ZERO != MCUXCLPKC_WAITFORFINISH_GETZERO())
            {
                MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
            }
        }
        else if(MCUXCLECC_SCALARMULT_OPTION_NO_OUTPUT_VALIDATION != (MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION_MASK & options))
        {
            MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
        }
        else
        {
            /* Do nothing */
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_TwEd_VarScalarMult, MCUXCLECC_STATUS_OK);
}
