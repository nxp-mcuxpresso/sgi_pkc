/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * @file  mcuxClEcc_ECDH_KeyAgreement.c
 * @brief ECC Weierstrass key agreement function
 */


#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClBuffer.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>

#include <mcuxClEcc.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_KeyHelper.h>
#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_ECDH_Internal.h>
#include <internal/mcuxClEcc_Internal_Random.h>
#include <internal/mcuxClEcc_Weier_Internal_FP.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>

#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_CopySecure_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClMath_Internal_Functions.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClPkc_Macros.h>

const mcuxClKey_AgreementDescriptor_t mcuxClKey_AgreementDescriptor_ECDH =
{
    .pAgreementFct = mcuxClEcc_ECDH_KeyAgreement,
    .protectionTokenAgreementFct = MCUX_CSSL_FP_FUNCID_mcuxClEcc_ECDH_KeyAgreement,
    .pProtocolDescriptor = NULL
};

/* TODO: hardening CLNS-16864 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_ECDH_KeyAgreement, mcuxClKey_AgreementFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_ECDH_KeyAgreement(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Agreement_t agreement,
    mcuxClKey_Handle_t key,
    mcuxClKey_Handle_t otherKey,
    mcuxClKey_Agreement_AdditionalInput_t additionalInputs[],
    uint32_t numberOfInputs,
    uint8_t * pOut,
    uint32_t * const pOutLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_ECDH_KeyAgreement);

    /* Verify that the key handles are correctly initialized for the ECDH use case */
    const mcuxClKey_AlgorithmId_t algorithmId = mcuxClKey_getAlgorithm(key);
    if( ( (MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP != algorithmId)
                && (MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM != algorithmId)
                && (MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP_EPHEMERAL_CUSTOM != algorithmId) )
            || mcuxClKey_getAlgorithm(key) != mcuxClKey_getAlgorithm(otherKey)
            || mcuxClKey_getTypeInfo(key) != mcuxClKey_getTypeInfo(otherKey)
            || MCUXCLKEY_ALGO_ID_PRIVATE_KEY != mcuxClKey_getKeyUsage(key)
            || MCUXCLKEY_ALGO_ID_PUBLIC_KEY != mcuxClKey_getKeyUsage(otherKey)
            )
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_FAILURE);
    }
    /* Unused input parameters */
    (void) agreement;
    (void) additionalInputs;
    (void) numberOfInputs;

    /**********************************************************/
    /* Initialization                                         */
    /**********************************************************/
    mcuxClEcc_Weier_DomainParams_t *pDomainParams = (mcuxClEcc_Weier_DomainParams_t *) mcuxClKey_getTypeInfo(key);
    const uint32_t byteLenP = pDomainParams->common.byteLenP;

    /* mcuxClEcc_CpuWa_t will be allocated and placed in the beginning of CPU workarea free space by SetupEnvironment. */
    mcuxClEcc_CpuWa_t *pCpuWorkarea = mcuxClEcc_castToEccCpuWorkArea(mcuxClSession_getEndOfUsedBuffer_Internal(pSession));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
    MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(pSession, 0u));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_WeierECC_SetupEnvironment(pSession,
                                    pDomainParams,
                                    ECC_KEYAGREEMENT_NO_OF_BUFFERS));

    /* Randomize coordinate buffers used within secure scalar multiplication (X0/Y0/X1/Y1). */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_RandomizeUPTRT(&pOperands[WEIER_X0],
                                                        (WEIER_Y1 - WEIER_X0 + 1u)) );

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("32-bit aligned UPTRT table is assigned in CPU workarea")
    uint32_t *pOperands32 = (uint32_t *) pOperands;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    const uint32_t bufferSize = operandSize + MCUXCLPKC_WORDSIZE;

    /**********************************************************/
    /* Load public key P                                      */
    /**********************************************************/

    /* Clear bytes on top of public key */
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(operandSize, byteLenP, UINT32_MAX);
    const uint32_t bytesToClear = operandSize - byteLenP;

    uint8_t *pPublicKeyXCoordDest = MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_XA]);
    uint8_t *pPublicKeyYCoordDest = MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_YA]);

    MCUX_CSSL_DI_RECORD(sumOfMemClearParamsX, &pPublicKeyXCoordDest[byteLenP]);
    MCUX_CSSL_DI_RECORD(sumOfMemClearParamsX, bytesToClear);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(&pPublicKeyXCoordDest[byteLenP], bytesToClear));

    MCUX_CSSL_DI_RECORD(sumOfMemClearParamsY, &pPublicKeyYCoordDest[byteLenP]);
    MCUX_CSSL_DI_RECORD(sumOfMemClearParamsY, bytesToClear);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(&pPublicKeyYCoordDest[byteLenP], bytesToClear));

    /* Load public key P to (XA,YA). */
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(otherKey));
    MCUXCLKEY_LOAD_FP(
      pSession,
      otherKey,
      &pPublicKeyXCoordDest,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
      NULL,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
      MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL);

    /* Check P in (XA,YA) affine NR. */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_XA);
    MCUX_CSSL_FP_FUNCTION_CALL(pointCheckStatus, mcuxClEcc_PointCheckAffineNR(pSession));
    if (MCUXCLECC_INTSTATUS_POINTCHECK_NOT_OK == pointCheckStatus)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_FAILURE);
    }
    else if (MCUXCLECC_STATUS_OK != pointCheckStatus)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Do nothing. */
    }


    /**********************************************************/
    /* Securely import secret scalar d and perform a secure   */
    /* scalar multiplication Q = d*P using a multiplicative   */
    /* splitting for d.                                       */
    /**********************************************************/

    uint8_t *pScalarDest = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S2]);

    /* Clear bytes on top of private key */
    const uint32_t byteLenN = pDomainParams->common.byteLenN;
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(operandSize, byteLenN, UINT32_MAX);
    const uint32_t bytesToClearPrivate = operandSize - byteLenN;
    MCUX_CSSL_DI_RECORD(sumOfMemClearParams, &pScalarDest[byteLenN]);
    MCUX_CSSL_DI_RECORD(sumOfMemClearParams, bytesToClearPrivate);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(&pScalarDest[byteLenN], bytesToClearPrivate));

    /* Securely import scalar d to buffer ECC_S2 */
//  MCUXCLPKC_WAITFORREADY();  <== there is WaitForFinish in mcuxClEcc_PointCheckAffineNR.
    // TODO: Initialize buffer with LQRNG data before import?
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(key));
    MCUXCLKEY_LOAD_FP(
      pSession,
      key,
      &pScalarDest,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
      NULL,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
      MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE);

    /* Call the BlindedScalarMult function.
     * If the function returns OK, WEIER_X0, WEIER_Y0, WEIER_Z contain the Jacobian coordinates of Q. */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_BlindedVarScalarMult, mcuxClEcc_BlindedVarScalarMult(pSession,
                                                                                      (mcuxClEcc_CommonDomainParams_t *) &pDomainParams->common) );
    if (MCUXCLECC_INTSTATUS_SCALAR_ZERO == ret_BlindedVarScalarMult)
    {
        /* Clear PKC workarea. */
        MCUXCLPKC_PS1_SETLENGTH(0u, bufferSize * ECC_KEYAGREEMENT_NO_OF_BUFFERS);
        pOperands[ECC_P] = MCUXCLPKC_PTR2OFFSET(pPkcWorkarea);
        MCUXCLPKC_FP_CALC_OP1_CONST(ECC_P, 0u);

        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_FAILURE);
    }
    else if (MCUXCLECC_STATUS_OK != ret_BlindedVarScalarMult)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Intentionally left empty */
    }

    /* Check the confidential point Q in randomized Jacobian coordinates before the conversion to affine coordinates. */
    MCUX_CSSL_FP_FUNCTION_CALL(pointCheckQStatusJacMR, mcuxClEcc_Weier_PointCheckJacMR(pSession));
    if (MCUXCLECC_STATUS_OK != pointCheckQStatusJacMR)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
    }

    /**********************************************************/
    /* Securely convert resulting point to affine coordinates */
    /**********************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_Weier_SecureConvertPoint_JacToAffine());

    /**********************************************************/
    /* Check n and p and export the resulting point.          */
    /**********************************************************/

    /* Import prime p and order n again, and check (compare with) existing one. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        mcuxClEcc_IntegrityCheckPN(pSession, (mcuxClEcc_CommonDomainParams_t *) &pDomainParams->common) );

    /* Securely export shared secret from WEIER_XA. */
    MCUXCLPKC_FP_SECUREEXPORTBIGENDIANFROMPKC_DI_BALANCED(pSession, pOut, WEIER_XA, byteLenP);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("caller-controlled variable. user must handle overflows.")
    *pOutLength += byteLenP;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    /* Clear PKC workarea. */
    MCUXCLPKC_PS1_SETLENGTH(0u, bufferSize * ECC_KEYAGREEMENT_NO_OF_BUFFERS);
    pOperands[ECC_P] = MCUXCLPKC_PTR2OFFSET(pPkcWorkarea);
    MCUXCLPKC_FP_CALC_OP1_CONST(ECC_P, 0u);

    mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
    MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

    mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_ECDH_KeyAgreement,
        MCUXCLECC_FP_ECDH_KEYAGREEMENT_FINAL);
}
