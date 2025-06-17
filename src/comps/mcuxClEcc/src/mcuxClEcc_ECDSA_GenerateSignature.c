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
 * @file  mcuxClEcc_ECDSA_GenerateSignature.c
 * @brief Weierstrass curve ECDSA signature generation API
 */


#include <stdint.h>
#include <stddef.h>

#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClBuffer.h>
#include <mcuxClEcc.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClSignature.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClMath_Internal_Utils.h>

#include <internal/mcuxClEcc_Internal_Random.h>
#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal_FP.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>
#include <internal/mcuxClEcc_ECDSA_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClEcc_Internal_KeyHelper.h>
#include <internal/mcuxClSignature_Internal.h>
#include <internal/mcuxClRandom_Internal_Functions.h>


/* TODO: Do sanity check for the input parameters. Ticket CLNS-7854 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_ECDSA_GenerateSignature, mcuxClSignature_SignFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClEcc_ECDSA_GenerateSignature(
  mcuxClSession_Handle_t   pSession,
  mcuxClKey_Handle_t       key,
  mcuxClSignature_Mode_t   mode,
  mcuxCl_InputBuffer_t     pIn,
  uint32_t                inSize,
  mcuxCl_Buffer_t          pSignature,
  uint32_t * const        pSignatureSize
  )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_ECDSA_GenerateSignature);

    /* Check which ECDSA variant shall be performed. */
    // TODO (CLNS-10703) Properly evaluate both possible options

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    const mcuxClEcc_ECDSA_SignatureProtocolDescriptor_t *pMode = (const mcuxClEcc_ECDSA_SignatureProtocolDescriptor_t *) mode->pProtocolDescriptor;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()
    if(MCUXCLECC_ECDSA_SIGNATURE_GENERATE_RANDOMIZED != pMode->generateOption)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    /**********************************************************/
    /* Initialization                                         */
    /**********************************************************/

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    mcuxClEcc_Weier_DomainParams_t *pDomainParams = (mcuxClEcc_Weier_DomainParams_t *) mcuxClKey_getTypeInfo(key);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    /* mcuxClEcc_CpuWa_t will be allocated and placed in the beginning of CPU workarea free space by SetupEnvironment. */
    /* MISRA Ex. 9 to Rule 11.3 - mcuxClEcc_CpuWa_t is 32 bit aligned */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - mcuxClEcc_CpuWa_t is 32 bit aligned")
    mcuxClEcc_CpuWa_t *pCpuWorkarea = (mcuxClEcc_CpuWa_t *) mcuxClSession_getEndOfUsedBuffer_Internal(pSession);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()
    uint8_t *pPkcWorkarea = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, 0u);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_WeierECC_SetupEnvironment(pSession,
                pDomainParams,
                       ECC_GENERATESIGNATURE_NO_OF_BUFFERS));

    /* Randomize coordinate buffers used within secure scalar multiplication (X0/Y0/X1/Y1). */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_RandomizeUPTRT(&pOperands[WEIER_X0],
                                                        (WEIER_Y1 - WEIER_X0 + 1u)) );

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("32-bit aligned UPTRT table is assigned in CPU workarea")
    uint32_t *pOperands32 = (uint32_t *) pOperands;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    const uint32_t bufferSize = operandSize + MCUXCLPKC_WORDSIZE;

    const uint32_t byteLenP = pDomainParams->common.byteLenP;
    const uint32_t byteLenN = pDomainParams->common.byteLenN;

    /* Main loop of signature generation until both r and s are nonzero. */
    uint32_t fail_r = 0u;
    uint32_t fail_s = 0u;
    MCUX_CSSL_FP_LOOP_DECL(MainLoop_R);
    MCUX_CSSL_FP_LOOP_DECL(MainLoop_S);
    do
    {
        /**********************************************************/
        /* Import and check base point G                          */
        /**********************************************************/

        /* Import G to (X1,Y1). */
        MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(WEIER_X1, pDomainParams->common.pGx, byteLenP, operandSize);
        MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(WEIER_Y1, pDomainParams->common.pGy, byteLenP, operandSize);

        /* Check G in (X1,Y1) affine NR. */
//      MCUXCLPKC_WAITFORREADY();  <== there is WaitForFinish in import function.
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_X1);
        MCUX_CSSL_FP_FUNCTION_CALL(pointCheckStatus, mcuxClEcc_PointCheckAffineNR(pSession));
        if (MCUXCLECC_STATUS_OK != pointCheckStatus)
        {
            MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
        }
        else
        {
            /* Do nothing. */
        }

        /**********************************************************/
        /* Generate multiplicative split ephemeral key k0 and k1, */
        /* k = k0 * k1 mod n, where k0 is a 64-bit odd number     */
        /**********************************************************/

        MCUX_CSSL_FP_FUNCTION_CALL(ret_CoreKeyGen, mcuxClEcc_Int_CoreKeyGen(pSession, byteLenN));
        if (MCUXCLECC_STATUS_OK != ret_CoreKeyGen)
        {
            if ( (MCUXCLECC_STATUS_RNG_ERROR == ret_CoreKeyGen)
                 && (0u == fail_r) && (0u == fail_s) )
            {
                mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
                MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

                mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

                MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_RNG_ERROR);
            }

            MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
        }

        MCUX_CSSL_FP_LOOP_ITERATION(MainLoop_R,
            MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_LOOP_R );


        /**********************************************************/
        /* Calculate Q = k1 * (k0 * G)                            */
        /**********************************************************/

        /* Convert coordinates of G to Montgomery representation. */
        MCUXCLPKC_FP_CALC_MC1_MM(WEIER_X0, WEIER_X1, ECC_PQSQR, ECC_P);
        MCUXCLPKC_FP_CALC_MC1_MM(WEIER_Y0, WEIER_Y1, ECC_PQSQR, ECC_P);
        MCUXCLPKC_FP_CALC_OP1_NEG(WEIER_Z, ECC_P);  /* 1 in MR */
        /* G will be randomized (projective coordinate randomization) in SecurePointMult. */

        /* Calculate Q0 = k0 * G. */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_SecurePointMult(ECC_S0, 64u));

        /* In case k1 is even, perform scalar multiplication k1 * Q0 by computing (n - k1) * (-Q0)
         *     as this avoids the exceptional case k1 = n-1. scalar modification will need to be reverted later on
         */
        MCUX_CSSL_FP_BRANCH_DECL(scalarEvenBranch);
        MCUXCLPKC_FP_CALC_OP1_LSB0s(ECC_S1);
        uint32_t k1NoOfTrailingZeros = MCUXCLPKC_WAITFORFINISH_GETZERO();
        if(MCUXCLPKC_FLAG_NONZERO == k1NoOfTrailingZeros)
        {
            MCUXCLPKC_FP_CALC_OP1_SUB(ECC_S1, ECC_N, ECC_S1);
            MCUXCLPKC_FP_CALC_MC1_MS(WEIER_Y0, ECC_PS, WEIER_Y0, ECC_PS);

            MCUX_CSSL_FP_BRANCH_POSITIVE(scalarEvenBranch,
                MCUXCLPKC_FP_CALLED_CALC_OP1_SUB,
                MCUXCLPKC_FP_CALLED_CALC_MC1_MS );
        }

        /* Calculate Q = k1 * Q0. */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_SecurePointMult(ECC_S1, byteLenN * 8u));
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(scalarEvenBranch, MCUXCLPKC_FLAG_NONZERO == k1NoOfTrailingZeros));


        /**********************************************************/
        /* Convert Q to affine coordinates and check              */
        /**********************************************************/

        /* T0 = ModInv(Z), where Z = (z * 256^LEN) \equiv z in MR. */
        MCUXCLMATH_FP_MODINV(ECC_T0, WEIER_Z, ECC_P, ECC_T1);
        /* T0 = z^(-1) * 256^(-LEN) \equiv z^(-1) * 256^(-2LEN) in MR. */

        /* Convert Q to affine coordinates. */
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_Weier_ConvertPoint_ToAffine,
                            mcuxClEcc_FUP_Weier_ConvertPoint_ToAffine_LEN);

        /* Check Q in (XA,YA) affine NR. */
        MCUXCLPKC_WAITFORREADY();
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_XA);
        MCUX_CSSL_FP_FUNCTION_CALL(pointCheckQStatus, mcuxClEcc_PointCheckAffineNR(pSession));
        if (MCUXCLECC_STATUS_OK != pointCheckQStatus)
        {
            MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
        }

        /**********************************************************/
        /* Calculate r = Q.x mod n, and check if r is zero        */
        /**********************************************************/

        MCUXCLPKC_FP_CALC_MC1_MS(WEIER_XA, WEIER_XA, ECC_N, ECC_N);  /* Hasse's theorem: Abs(n - (p+1)) <= 2 * sqrt(p). */

        fail_r += MCUXCLPKC_WAITFORFINISH_GETZERO();
        if (MCUXCLPKC_FLAG_ZERO == MCUXCLPKC_GETZERO())
        {
            continue;
        }

        /**********************************************************/
        /* Securely import private key                            */
        /**********************************************************/

        uint8_t *pPrivateKeyDest = MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_ZA]);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_load));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_load(pSession,
                                                                   key,
                                                                   &pPrivateKeyDest,
                                                                   MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
                                                                   NULL,
                                                                   MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                                   MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE));

        /* Generate random number d1 (to blind the private key). */
        uint8_t * const ptrZ = MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_Z]);
        MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();  // avoid CPU accessing to PKC workarea when PKC is busy
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_ncGenerate_Internal(pSession, ptrZ, operandSize));


        /**********************************************************/
        /* Import message hash, and truncate if longer than n     */
        /**********************************************************/

        /* Import message digest to buffer ECC_S2 and pad or truncate it */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_ECDSA_PrepareMessageDigest(pIn,
                                         inSize,
                                         byteLenN));

        MCUX_CSSL_FP_LOOP_ITERATION(MainLoop_S, MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_LOOP_S );


        /**********************************************************/
        /* Securely calculate signature s, and check if s is zero */
        /**********************************************************/
        /* Revert scalar modification by computing n-k1 in place again before calculating signature s */
        if(MCUXCLPKC_FLAG_NONZERO == k1NoOfTrailingZeros)
        {
            MCUXCLPKC_FP_CALC_OP1_SUB(ECC_S1, ECC_N, ECC_S1);
            MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_SUB);
        }
        /* Now, XA = r,  S2 = z (hash of message);   */
        /*      S0 = k0, S1 = k1, k = k0 * k1 mod n; */
        /*      ZA = d,  Z  = d1.                    */
        /* s = k^(-1) * (z + r * d) = (k0*k1)^(-1) * (z + r * (d0-d1)) mod n. */

        /* T1 = s'  = k1*(z+r*d) * R^(-2) mod n <= n; */
        /* T2 = k0' = (k*k1) * R^(-3) mod n.          */
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_Weier_Sign_CalculateS,
                            mcuxClEcc_FUP_Weier_Sign_CalculateS_LEN);

        /* T0 = h0 = ModInv(k0') = (k*k1)^(-1) * R^3 mod n. */
        MCUXCLMATH_FP_MODINV(ECC_T0, ECC_T2, ECC_N, ECC_T3);

        /* YA = s = h0 * s' - n mod n < n. */
        /* MM(h0, s') < 2n because s' <= n. */
        MCUXCLPKC_FP_CALC_MC1_MM(WEIER_YA, ECC_T0, ECC_T1, ECC_N);
        MCUXCLPKC_FP_CALC_MC1_MS(WEIER_YA, WEIER_YA, ECC_N, ECC_N);

        fail_s += MCUXCLPKC_WAITFORFINISH_GETZERO();

    } while(MCUXCLPKC_FLAG_ZERO == MCUXCLPKC_GETZERO());


    /**********************************************************/
    /* Check n and p and export signature r and s             */
    /**********************************************************/

    /* Import prime p and order n again, and check (compare with) existing one. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        mcuxClEcc_IntegrityCheckPN(pSession, (mcuxClEcc_CommonDomainParams_t *) &pDomainParams->common));
        *pSignatureSize += (byteLenN * 2u);

    MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFER_DI_BALANCED(mcuxClEcc_ECDSA_GenerateSignature, pSignature, WEIER_XA, byteLenN);
    MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFEROFFSET_DI_BALANCED(mcuxClEcc_ECDSA_GenerateSignature, pSignature, WEIER_YA, byteLenN, byteLenN);

    /* Clear PKC workarea. */
    MCUXCLPKC_PS1_SETLENGTH(0u, bufferSize * ECC_GENERATESIGNATURE_NO_OF_BUFFERS);
    pOperands[ECC_P] = MCUXCLPKC_PTR2OFFSET(pPkcWorkarea);
    MCUXCLPKC_FP_CALC_OP1_CONST(ECC_P, 0u);

    mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
    MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

    mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_ECDSA_GenerateSignature, MCUXCLECC_STATUS_OK,
        MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_BEFORE_LOOP,
        MCUX_CSSL_FP_LOOP_ITERATIONS(MainLoop_R, fail_r + fail_s + 1u),
        MCUX_CSSL_FP_LOOP_ITERATIONS(MainLoop_S, fail_s + 1u),
        MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_FINAL);
}
