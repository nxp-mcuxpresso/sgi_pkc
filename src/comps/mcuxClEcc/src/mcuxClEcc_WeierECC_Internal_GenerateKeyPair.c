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
 * @file  mcuxClEcc_WeierECC_Internal_GenerateKeyPair.c
 * @brief ECC Weierstrass key pair generation function
 */


#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClBuffer.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClPkc_Macros.h>

#include <mcuxClEcc.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_WeierECC_Internal_GenerateKeyPair.h>
#include <internal/mcuxClEcc_Weier_Internal_FP.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>

#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_ECDSA =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    .pKeyGenFct = mcuxClEcc_WeierECC_GenerateKeyPair,
    .protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClEcc_WeierECC_GenerateKeyPair,
    .pProtocolDescriptor = NULL
};

const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_ECDH =
{
    .pKeyGenFct = mcuxClEcc_WeierECC_GenerateKeyPair,
    .protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCID_mcuxClEcc_WeierECC_GenerateKeyPair,
    .pProtocolDescriptor = NULL
};

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_WeierECC_GenerateKeyPair, mcuxClKey_KeyGenFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_WeierECC_GenerateKeyPair(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Generation_t generation,
    mcuxClKey_Handle_t privKey,
    mcuxClKey_Handle_t pubKey)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_WeierECC_GenerateKeyPair);

    /* Verify that the key handles are correctly initialized for the ECC use case */
    const mcuxClKey_AlgorithmId_t algorithmId_privKey = mcuxClKey_getAlgorithm(privKey);

    if( ( (MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP != algorithmId_privKey)
                && (MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM != algorithmId_privKey)
                && (MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP_EPHEMERAL_CUSTOM != algorithmId_privKey) )
            || algorithmId_privKey != mcuxClKey_getAlgorithm(pubKey)
            || mcuxClKey_getTypeInfo(privKey) != mcuxClKey_getTypeInfo(pubKey)
            || MCUXCLKEY_ALGO_ID_PRIVATE_KEY != mcuxClKey_getKeyUsage(privKey)
            || MCUXCLKEY_ALGO_ID_PUBLIC_KEY != mcuxClKey_getKeyUsage(pubKey)
            )
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_FAILURE);
    }
    else
    {
        /* Unused input parameters */
        (void) generation;

        /**********************************************************/
        /* Initialization                                         */
        /**********************************************************/
        mcuxClEcc_Weier_DomainParams_t *pDomainParams = (mcuxClEcc_Weier_DomainParams_t *) mcuxClKey_getTypeInfo(privKey);

        /* mcuxClEcc_CpuWa_t will be allocated and placed in the beginning of CPU workarea free space by SetupEnvironment. */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - mcuxClEcc_CpuWa_t is 32 bit aligned")
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
        MCUX_CSSL_FP_FUNCTION_CALL(mcuxClEcc_CpuWa_t*, pCpuWorkarea, mcuxClSession_allocateWords_cpuWa(pSession, 0u));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
        MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(pSession, 0u));

        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_WeierECC_SetupEnvironment(pSession,
                                        pDomainParams,
                                        ECC_GENERATEKEYPAIR_NO_OF_BUFFERS));

        /* Randomize coordinate buffers used within secure scalar multiplication (X0/Y0/X1/Y1). */
        uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_RandomizeUPTRT(&pOperands[WEIER_X0],
                                                            (WEIER_Y1 - WEIER_X0 + 1u)) );

        MCUXCLMATH_FP_QSQUARED(ECC_NQSQR, ECC_NS, ECC_N, ECC_T0);

        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("32-bit aligned UPTRT table is assigned in CPU workarea")
        uint32_t *pOperands32 = (uint32_t *) pOperands;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
        const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
        const uint32_t bufferSize = operandSize + MCUXCLPKC_WORDSIZE;

        const uint32_t byteLenP = pDomainParams->common.byteLenP;
        const uint32_t byteLenN = pDomainParams->common.byteLenN;

        /**********************************************************/
        /* Import and check base point G                          */
        /**********************************************************/

        /* Import G to (X1,Y1). */
        MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(WEIER_X1, pDomainParams->common.pGx, byteLenP, operandSize);
        MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(WEIER_Y1, pDomainParams->common.pGy, byteLenP, operandSize);

        /* Check G in (X1,Y1) affine NR. */
    //  MCUXCLPKC_WAITFORREADY();  <== there is WaitForFinish in import function.
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_X1);
        MCUX_CSSL_FP_FUNCTION_CALL(pointCheckStatus, mcuxClEcc_PointCheckAffineNR(pSession));
        if (MCUXCLECC_STATUS_OK != pointCheckStatus)
        {
            MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
        }


        /**********************************************************/
        /* Generate multiplicative split private key d0 and d1,   */
        /* d = d0 * d1 mod n, where d0 is a 64-bit odd number.    */
        /**********************************************************/

        MCUX_CSSL_FP_FUNCTION_CALL(ret_CoreKeyGen, mcuxClEcc_Int_CoreKeyGen(pSession, byteLenN));
        if (MCUXCLECC_STATUS_OK != ret_CoreKeyGen)
        {
            if (MCUXCLECC_STATUS_RNG_ERROR == ret_CoreKeyGen)
            {
                mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
                MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

                mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

                MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_FAILURE);
            }

            MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
        }

        /**********************************************************/
        /* Derive the plain private key d = d0 * d1 mod n < n.    */
        /**********************************************************/

        /* Compute d in S2 using a blinded multiplication utilizing the random still stored in S3 after mcuxClEcc_Int_CoreKeyGen. */
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_Weier_KeyGen_DerivePlainPrivKey,
                            mcuxClEcc_FUP_Weier_KeyGen_DerivePlainPrivKey_LEN);

        /**********************************************************/
        /* Calculate public key Q = d1 * (d0 * G)                 */
        /**********************************************************/

        /* Convert coordinates of G to Montgomery representation. */
        MCUXCLPKC_FP_CALC_MC1_MM(WEIER_X0, WEIER_X1, ECC_PQSQR, ECC_P);
        MCUXCLPKC_FP_CALC_MC1_MM(WEIER_Y0, WEIER_Y1, ECC_PQSQR, ECC_P);
        MCUXCLPKC_FP_CALC_OP1_NEG(WEIER_Z, ECC_P);  /* 1 in MR */
        /* G will be randomized (projective coordinate randomization) in SecurePointMult. */

        /* Calculate Q0 = d0 * G. */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_SecurePointMult(ECC_S0, 64u));

        /* In case d1 is even, perform scalar multiplication d1 * Q0 by computing (n-d1) * (-Q0) as this avoids the exceptional case d1 = n-1 */
        MCUX_CSSL_FP_BRANCH_DECL(scalarEvenBranch);
        MCUXCLPKC_FP_CALC_OP1_LSB0s(ECC_S1);
        uint32_t d1NoOfTrailingZeros = MCUXCLPKC_WAITFORFINISH_GETZERO();
        if(MCUXCLPKC_FLAG_NONZERO == d1NoOfTrailingZeros)
        {
            MCUXCLPKC_FP_CALC_OP1_SUB(ECC_S1, ECC_N, ECC_S1);
            MCUXCLPKC_FP_CALC_MC1_MS(WEIER_Y0, ECC_PS, WEIER_Y0, ECC_PS);

            MCUX_CSSL_FP_BRANCH_POSITIVE(scalarEvenBranch,
                MCUXCLPKC_FP_CALLED_CALC_OP1_SUB,
                MCUXCLPKC_FP_CALLED_CALC_MC1_MS );
        }

        /* Calculate Q = d1 * Q0. */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_SecurePointMult(ECC_S1, byteLenN * 8u));
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(scalarEvenBranch, MCUXCLPKC_FLAG_NONZERO == d1NoOfTrailingZeros));


        /**********************************************************/
        /* Convert public key to affine coordinates and check     */
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
            MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
        }


        /**********************************************************/
        /* Check n and p and export private and public key.       */
        /**********************************************************/

        /* Import prime p and order n again, and check (compare with) existing one. */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(
            mcuxClEcc_IntegrityCheckPN(pSession, (mcuxClEcc_CommonDomainParams_t *) &pDomainParams->common));

        /* Store private key into key handle */
        uint8_t *pPrivKeySrc = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S2]);
        MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(privKey));
        MCUXCLKEY_STORE_FP(
            pSession,
            privKey,
            pPrivKeySrc,
            0u);

        /* Store public key into key handle */
        uint8_t *pPubKeyXSrc = MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_XA]);
        MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(pubKey));
        MCUXCLKEY_STORE_FP(
            pSession,
            pubKey,
            pPubKeyXSrc,
            0u);

        /* Create link between private and public key handles */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_linkKeyPair(pSession, privKey, pubKey));

        /* Clear PKC workarea. */
        MCUXCLPKC_PS1_SETLENGTH(0u, bufferSize * ECC_GENERATEKEYPAIR_NO_OF_BUFFERS);
        pOperands[ECC_P] = MCUXCLPKC_PTR2OFFSET(pPkcWorkarea);
        MCUXCLPKC_FP_CALC_OP1_CONST(ECC_P, 0u);

        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_WeierECC_GenerateKeyPair,
                                    MCUXCLECC_FP_GENERATEKEYPAIR_FINAL,
                                    MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
                                    MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
    }
}
