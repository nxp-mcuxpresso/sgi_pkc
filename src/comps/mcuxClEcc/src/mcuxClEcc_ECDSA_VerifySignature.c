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

/**
 * @file  mcuxClEcc_ECDSA_VerifySignature.c
 * @brief Weierstrass curve ECDSA signature verification API
 */


#include <stdint.h>
#include <stddef.h>

#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxClBuffer.h>
#include <mcuxClEcc.h>
#include <mcuxClSignature.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_Compare_Internal.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClMath_Internal_Utils.h>

#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal_FP.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClEcc_ECDSA_Internal.h>
#include <internal/mcuxClEcc_Internal_KeyHelper.h>

/**
 * This function checks if an ECDSA signature (r,s) is in proper range, i.e. it satisfies 0 < r,s < n.
 *
 * Return values:
 *  - MCUXCLECC_STATUS_OK                 if the range check passed and the function executed successfully
 *  - MCUXCLECC_STATUS_INVALID_SIGNATURE  if the range check failed, i.e. the signature is invalid
 *
 * Prerequisites:
 *  - ps1Len = (operandSize, operandSize)
 *  - Buffer ECC_NFULL contains n'||n
 *  - The signature values r and s are stored in ECC_S3 and ECC_T1, respectively.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_ECDSA_SignatureRangeCheck)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_ECDSA_SignatureRangeCheck(void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_ECDSA_SignatureRangeCheck);

    /* If r < n, then ECC_T2 = r; otherwise ECC_T2 = r - n. */
    MCUXCLPKC_FP_CALC_MC1_MS(ECC_T2, ECC_S3, ECC_N, ECC_N);

    /* Check r != 0, r != n. */
    if (MCUXCLPKC_FLAG_ZERO == MCUXCLPKC_WAITFORFINISH_GETZERO())
    {   /* r = 0 or n. */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_SignatureRangeCheck, MCUXCLECC_STATUS_INVALID_SIGNATURE,
            MCUXCLPKC_FP_CALLED_CALC_MC1_MS);
    }

    /* Check r < n. */
    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_S3, ECC_N);
    if (MCUXCLPKC_FLAG_CARRY != MCUXCLPKC_WAITFORFINISH_GETCARRY())
    {   /* r > n. */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_SignatureRangeCheck, MCUXCLECC_STATUS_INVALID_SIGNATURE,
            MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP);
    }

    /* If s < n, then ECC_T3 = s; otherwise ECC_T3 = s - n. */
    MCUXCLPKC_FP_CALC_MC1_MS(ECC_T3, ECC_T1, ECC_N, ECC_N);

    /* Check s != 0, s != n. */
    if (MCUXCLPKC_FLAG_ZERO == MCUXCLPKC_WAITFORFINISH_GETZERO())
    {   /* s = 0 or n. */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_SignatureRangeCheck, MCUXCLECC_STATUS_INVALID_SIGNATURE,
            MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
            MCUXCLPKC_FP_CALLED_CALC_MC1_MS);
    }

    /* Check s < n. */
    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_T1, ECC_N);
    if (MCUXCLPKC_FLAG_CARRY != MCUXCLPKC_WAITFORFINISH_GETCARRY())
    {   /* s > n. */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_SignatureRangeCheck, MCUXCLECC_STATUS_INVALID_SIGNATURE,
            MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
            MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_SignatureRangeCheck, MCUXCLECC_STATUS_OK,
        MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
        MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP);
}


// TODO: Add sanity checks on the key CLNS-7854
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_ECDSA_VerifySignature, mcuxClSignature_VerifyFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClEcc_ECDSA_VerifySignature(
    mcuxClSession_Handle_t   pSession,
    mcuxClKey_Handle_t       key,
    mcuxClSignature_Mode_t   mode,
    mcuxCl_InputBuffer_t     pIn,
    uint32_t                inSize,
    mcuxCl_InputBuffer_t     pSignature,
    uint32_t                signatureSize
    )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_ECDSA_VerifySignature);

    /* Unused input parameters */
    (void) mode;

    /**********************************************************/
    /* Initialization                                         */
    /**********************************************************/
    /* TODO: Do sanity check for the input parameters. Ticket CLNS-7854 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    mcuxClEcc_Weier_DomainParams_t *pDomainParams = (mcuxClEcc_Weier_DomainParams_t *) mcuxClKey_getTypeInfo(key);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()
    const uint32_t byteLenN = pDomainParams->common.byteLenN;

    if (signatureSize != byteLenN * 2u)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
    }

    /* mcuxClEcc_CpuWa_t will be allocated and placed in the beginning of CPU workarea free space by SetupEnvironment. */
    mcuxClEcc_CpuWa_t *pCpuWorkarea = mcuxClEcc_castToEccCpuWorkArea(mcuxClSession_getEndOfUsedBuffer_Internal(pSession));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_WeierECC_SetupEnvironment(pSession,
                 pDomainParams,
                        ECC_VERIFYSIGNATURE_NO_OF_BUFFERS));

    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("32-bit aligned UPTRT table is assigned in CPU workarea")
    uint32_t *pOperands32 = (uint32_t *) pOperands;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();

    /**********************************************************/
    /* Import signature r and s, and                          */
    /* check both r,s are in range [1, n-1]                   */
    /**********************************************************/

    /* Import r to S3 and s to T1. */
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_ECDSA_VerifySignature, ECC_S3, pSignature, byteLenN, operandSize);
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFEROFFSET_DI_BALANCED(mcuxClEcc_ECDSA_VerifySignature, ECC_T1, pSignature, byteLenN, byteLenN, operandSize);

    /* Verify that r and s are in range [1,n-1] */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_SignatureRangeCheck, mcuxClEcc_ECDSA_SignatureRangeCheck());
    if (MCUXCLECC_STATUS_INVALID_SIGNATURE == ret_SignatureRangeCheck)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("insufficient workarea (pCpuWorkarea = NULL) will be checked in SetupEnvironment")
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_DI_RECORD(mcuxClEcc_ECDSA_VerifySignature_return, MCUXCLECC_STATUS_INVALID_SIGNATURE);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_VerifySignature, MCUXCLECC_STATUS_INVALID_SIGNATURE,
            MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_INIT,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ECDSA_SignatureRangeCheck),
            MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
    }


    /**********************************************************/
    /* Import message hash, and truncate if longer than n     */
    /**********************************************************/

    /* Import message digest to buffer ECC_S2 and pad or truncate it */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_ECDSA_PrepareMessageDigest(pIn,
                                    inSize,
                                    byteLenN));

    /* Check if hash is 0 modulo n (one subtraction is enough, because bit length of hash <= bit length of n). */
    MCUXCLPKC_FP_CALC_MC1_MS(ECC_S2, ECC_S2, ECC_N, ECC_N);
    uint32_t checkHashZero = MCUXCLPKC_WAITFORFINISH_GETZERO();


    /**********************************************************/
    /* Calculate s^(-1), and                                  */
    /* u1 = hash * s^(-1) mod n and u2 = r * s^(-1) mod n     */
    /**********************************************************/

    /* Calculate s^(-1) * 256^LEN mod n. */
    MCUXCLPKC_FP_CALC_MC1_MR(ECC_T2, ECC_T1, ECC_N);      // t2 = s * (256^LEN)^(-1)
    MCUXCLMATH_FP_MODINV(ECC_T1, ECC_T2, ECC_N, ECC_T3);  // t1 = t2^(-1) = s^(-1) * 256^LEN, using T3 as temp

    /* Initialize z coordinate, z = 1 in MR, in Z. */
    /* Calculate u1 and u2, store result in S0 and S1. */
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_Fup_Verify_InitZ_CalcU1U2,
                        mcuxClEcc_Fup_Verify_InitZ_CalcU1U2_LEN);
    /* Check if u1 is zero. */
    if (checkHashZero != MCUXCLPKC_WAITFORFINISH_GETZERO())
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }


    /**********************************************************/
    /* Calculate P1 = u1 * G                                  */
    /**********************************************************/

    /* Interleave u1 in S0 and u2 in S1. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_InterleaveTwoScalars(MCUXCLPKC_PACKARGS2(ECC_S0, ECC_S1), byteLenN * 8u));

    /* Calculate P1 = u1 * G, if u1 != 0 */
    if (MCUXCLPKC_FLAG_ZERO != checkHashZero)
    {
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(
            pDomainParams->common.pScalarMultFunctions->plainFixScalarMultFct(
                pSession,
                (mcuxClEcc_CommonDomainParams_t *)&pDomainParams->common,
                ECC_S0,
                byteLenN * 8u,
                MCUXCLECC_SCALARMULT_OPTION_AFFINE_INPUT |
                MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_OUTPUT |
                MCUXCLECC_SCALARMULT_OPTION_NO_OUTPUT_VALIDATION)); // TODO (CLNS-13627): Move mcuxClEcc_PointCheckAffineNR into the function
    }

    /* Reset z' = 1 in MR (or initialize z' if u1 == 0). */
    MCUXCLPKC_FP_CALC_OP1_NEG(WEIER_ZA, ECC_P);


    /**********************************************************/
    /* Calculate P2 = u2 * Q, and update P1 accordingly       */
    /**********************************************************/

    /* Load affine coordinates of public key Q to buffers (X1,Y1) in affine NR and clear any potential garbage
     * in these buffers as a preparation for the following point validation. */
    uint8_t *pPubKeyX = MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_X1]);
    uint8_t *pPubKeyY = MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_Y1]);
    MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();  // avoid CPU accessing to PKC workarea when PKC is busy
    const uint32_t byteLenP = pDomainParams->common.byteLenP;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("operandSize is by definition not smaller than byteLenP.")
    const uint32_t bytesToClear = operandSize - byteLenP;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    MCUX_CSSL_DI_RECORD(sumOfMemClearParamsX, (uint32_t)&pPubKeyX[byteLenP] + bytesToClear);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(&pPubKeyX[byteLenP], bytesToClear));

    MCUX_CSSL_DI_RECORD(sumOfMemClearParamsY, (uint32_t)&pPubKeyY[byteLenP] + bytesToClear);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(&pPubKeyY[byteLenP], bytesToClear));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_load(pSession,
                                                              key,
                                                              &pPubKeyX,
                                                              MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
                                                              NULL,
                                                              MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                              MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL));


    /* Check Q in (X1,Y1) affine NR. */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_X1);
    MCUX_CSSL_FP_FUNCTION_CALL(pointCheckPubKeyStatus, mcuxClEcc_PointCheckAffineNR(pSession));
    if (MCUXCLECC_INTSTATUS_POINTCHECK_NOT_OK == pointCheckPubKeyStatus)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
    }

    /* Convert Q: (X1,Y1) affine NR -> (X0,Y0, Z) Jacobian. */
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_Fup_Verify_Convert_pubkeyQ_toJacobianMR,
                        mcuxClEcc_Fup_Verify_Convert_pubkeyQ_toJacobianMR_LEN);

    /* Calculate PrecQ = (2^(byteLenN *4)) * Q. */
    /* Input: Q in (X0,Y0, ZA=1) relative-z.    */
    /* Output: PrecQ in (X3,Y3, ZA) relative-z. */
//  MCUXCLPKC_WAITFORREADY();  <== unnecessary, because VX0/VY0/VZ0/VZ/VX2/VY2/VZ2 are not used in the FUP program before.
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_X3);  /* output: PrecQ */
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VZ0, WEIER_ZA);   /* input: z, z'; output z' */
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX2, WEIER_X0);  /* input: Q */
    pOperands[WEIER_VZ2] = pOperands[WEIER_ZA];
    pOperands[WEIER_VT] = pOperands[ECC_S2];  /* Use S2 as 5th temp. */

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_RepeatPointDouble((byteLenN * 8u) / 2u));

    /* Prepare 3 pre-computed points for Q, with the same z coordinate. */
    /* Input: Q     in (X0, Y0, Z) Jacobian;                       */
    /*        PrecQ in (X3, Y3, ZA) relative-z.                    */
    /* Output: Prec1 = Q (unchanged)   in (X0, Y0, Z) Jacobian;    */
    /*         Prec2 = PrecQ (updated) in (X2, Y2, ZA) relative-z; */
    /*         Prec3 = Q + PrecQ       in (X3, Y3, ZA) relative-z. */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VT2, WEIER_X2);  /* output: Prec2 */
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_X3);  /* input: PrecQ; output: Prec3 */
    pOperands[WEIER_VZ0] = pOperands[WEIER_ZA];                        /* input/output: z' */
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX1, WEIER_X0);  /* input: Q */
    MCUXCLECC_FP_CALCFUP_ADD_ONLY();

    /* Update Q:  (X0,Y0, old Z) -> (X1,Y1, new Z) Jacobian; */
    /*        P1: (XA,YA, old Z) -> (X0,Y0, new Z) Jacobian. */
    /* Update z = z * z'. */
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_Fup_Verify_Update_pubkeyQ_P1_z,
                        mcuxClEcc_Fup_Verify_Update_pubkeyQ_P1_z_LEN);

    /* Calculate P2 = u2 * Q. */
    /* Input: 3 Prec_i, in (Xi,Yi, Z) Jacobian.        */
    /* Output: P2 in (XA,YA, ZA) relative-z, w.r.t. Z. */
//  pOperands[WEIER_VT] = pOperands[ECC_S2];  <== the 5th temp WEIER_VT has been set before calling _RepeatPointDouble.

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_Int_PointMult(ECC_S1, byteLenN * 8u));

    /**********************************************************/
    /* Calculate (x1, y1) = P1 + P2, and check the result     */
    /**********************************************************/

    /* Calculate P2 += P1, if u1 != 0. */
    if (MCUXCLPKC_FLAG_ZERO != checkHashZero)
    {
        /* Input: P1 in (X0,Y0, Z) Jacobian;          */
        /*        P2 in (XA,YA, ZA) relative-z.       */
        /* Output: P1 + P2 in (XA,YA, ZA) relative-z. */
        MCUXCLPKC_WAITFORREADY();
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_XA);   /* input: P2; output P1 + P2 */
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VZ0, WEIER_ZA);   /* input: z' and z; output z' */
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX1, WEIER_X0);   /* input: P1 */
        MCUX_CSSL_FP_FUNCTION_CALL(statusPointFullAdd, mcuxClEcc_PointFullAdd());
        if (MCUXCLECC_STATUS_NEUTRAL_POINT == statusPointFullAdd)
        {
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("insufficient workarea (pCpuWorkarea = NULL) will be checked in SetupEnvironment")
            mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
            MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

            mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

            MCUX_CSSL_DI_RECORD(mcuxClEcc_ECDSA_VerifySignature_return, MCUXCLECC_STATUS_INVALID_SIGNATURE);
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_VerifySignature, MCUXCLECC_STATUS_INVALID_SIGNATURE,
                MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_INIT,
                MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_PREPARE_AND_CHECK,
                MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P1,
                MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P2,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointFullAdd),
                MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
        }
    }

    /* Convert P1 + P2 (or P2 if u1 == 0) to (X0,Y0), affine NR. */
    /* Calculate R = x mod n, in X1. */
    MCUXCLPKC_FP_CALC_MC1_MM(ECC_T0, WEIER_Z, WEIER_ZA, ECC_P);  // t0 = z*z' * 256^LEN         = z*z' in MR
    MCUXCLMATH_FP_MODINV(ECC_T1, ECC_T0, ECC_P, ECC_T2);     // t1 = (z*z')^(-1) * 256^(-LEN), use T2 as temp
    /* MISRA Ex. 22, while(0) is allowed */
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_Fup_Verify_Convert_P1plusP2_toAffineNR_CalcR,
                        mcuxClEcc_Fup_Verify_Convert_P1plusP2_toAffineNR_CalcR_LEN);

    /* Check if P1 + P2 is valid. */
//  MCUXCLPKC_WAITFORREADY();  <== unnecessary, because VX0/VY0 are not used in the FUP program before.
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_X0);
    MCUX_CSSL_FP_FUNCTION_CALL(pointCheckStatus, mcuxClEcc_PointCheckAffineNR(pSession));
    if (MCUXCLECC_STATUS_OK != pointCheckStatus)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    /**********************************************************/
    /* Check r = (x mod n) robustly, and check p and n        */
    /**********************************************************/

    /* Check if imported signature R is equal to the calculated R. */
    MCUXCLPKC_FP_CALC_OP1_CMP(WEIER_X1, ECC_S3);
    volatile uint32_t zeroFlag_checkR = MCUXCLPKC_WAITFORFINISH_GETZERO();


    if ((MCUXCLPKC_FLAG_ZERO != zeroFlag_checkR)
    )
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("insufficient workarea (pCpuWorkarea = NULL) will be checked in SetupEnvironment")
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_DI_RECORD(mcuxClEcc_ECDSA_VerifySignature_return, MCUXCLECC_STATUS_INVALID_SIGNATURE);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_VerifySignature, MCUXCLECC_STATUS_INVALID_SIGNATURE,
            MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_INIT,
            MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_PREPARE_AND_CHECK,
            MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P1,
            MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P2,
            MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P1_ADD_P2,
            MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
    }


    /**********************************************************/
    /* Clean up and exit                                      */
    /**********************************************************/

    /* Export the calculated r. */
    uint8_t computedRForComparison[MCUXCLECC_WEIERECC_MAX_SIZE_BASEPOINTORDER];
    MCUXCLBUFFER_INIT(buffComputedR, NULL, computedRForComparison, byteLenN);
    MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFER_DI_BALANCED(mcuxClEcc_ECDSA_VerifySignature, buffComputedR, WEIER_X1, byteLenN);

    /* Import prime p and order n again, and check (compare with) existing one. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        mcuxClEcc_IntegrityCheckPN(pSession, (mcuxClEcc_CommonDomainParams_t *) &pDomainParams->common));

    /* Save the CRC of the computed R value in the session (if the security option is enabled) */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSession_computeAndSetCrcForExternalVerification(pSession, computedRForComparison, byteLenN));

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("insufficient workarea (pCpuWorkarea = NULL) will be checked in SetupEnvironment")
    mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
    MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

    mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

    /* Record MCUXCLECC_STATUS_OK, as zeroFlag_checkR should equal MCUXCLPKC_FLAG_ZERO */
    MCUX_CSSL_DI_RECORD(mcuxClEcc_ECDSA_VerifySignature_return, MCUXCLECC_STATUS_OK);
    uint32_t retCode =  (MCUXCLECC_STATUS_OK ^ MCUXCLPKC_FLAG_ZERO) ^ zeroFlag_checkR;
    MCUX_CSSL_FP_FUNCTION_EXIT(
      mcuxClEcc_ECDSA_VerifySignature,
      retCode,
      MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_INIT,
      MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_PREPARE_AND_CHECK,
      MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P1,
      MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P2,
      MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P1_ADD_P2,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_IntegrityCheckPN),
      /* Clean up and exit */
      MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFER,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_computeAndSetCrcForExternalVerification),
      MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
}
