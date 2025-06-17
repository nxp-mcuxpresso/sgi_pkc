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
 * @file  mcuxClEcc_MontDH_KeyAgreement.c
 * @brief mcuxClEcc: implementation of MontDH key agreement function acc to rfc 7748
 */


#include <stdint.h>

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClEcc.h>
#include <mcuxClEcc_MemoryConsumption.h>
#include <mcuxCsslParamIntegrity.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClEcc_Internal_KeyHelper.h>
#include <internal/mcuxClEcc_Mont_Internal.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClKey_Functions_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_MontDH_KeyAgreement, mcuxClKey_AgreementFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_MontDH_KeyAgreement(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Agreement_t agreement UNUSED_PARAM,
    mcuxClKey_Handle_t key,
    mcuxClKey_Handle_t otherKey,
    mcuxClKey_Agreement_AdditionalInput_t additionalInputs[] UNUSED_PARAM,
    uint32_t numberOfInputs UNUSED_PARAM,
    uint8_t * pOut,
    uint32_t * const pOutLength )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_MontDH_KeyAgreement);

    mcuxClKey_Descriptor_t * pKey = (mcuxClKey_Descriptor_t *)key;
    mcuxClKey_Descriptor_t * pOtherKey = (mcuxClKey_Descriptor_t *)otherKey;

    if(((MCUXCLKEY_ALGO_ID_ECC_MONTDH | MCUXCLKEY_ALGO_ID_PRIVATE_KEY) != mcuxClKey_getAlgoId(pKey)) || (MCUXCLKEY_SIZE_NOTUSED == mcuxClKey_getSize(pKey)) ||
       ((MCUXCLKEY_ALGO_ID_ECC_MONTDH | MCUXCLKEY_ALGO_ID_PUBLIC_KEY) != mcuxClKey_getAlgoId(pOtherKey) || (MCUXCLKEY_SIZE_NOTUSED == mcuxClKey_getSize(pOtherKey))) )
    {
       MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
    }

    /* Set up the environment */
    mcuxClEcc_MontDH_DomainParams_t *pDomainParameters = (mcuxClEcc_MontDH_DomainParams_t *)mcuxClKey_getTypeInfo(pKey);
    mcuxClEcc_CommonDomainParams_t *pCommonDomainParameters = &(pDomainParameters->common);

    /* SREQI_MONTDH_7 - DI protect shifting amounts for scalar decoding */
    /* Compensates EXPUNGES in mcuxClEcc_MontDH_DecodeScalar function    */
    MCUX_CSSL_DI_RECORD(shiftAmount, (uint32_t)pDomainParameters->c);
    MCUX_CSSL_DI_RECORD(shiftAmount, (uint32_t)pDomainParameters->t);

    /* For Curve25519 and Curve448, private and public keys have the same length as the prime p */
    uint16_t keyLen = pCommonDomainParameters->byteLenP;

    /* mcuxClEcc_CpuWa_t will be allocated and placed in the beginning of CPU workarea free space by SetupEnvironment. */
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClEcc_CpuWa_t *pCpuWorkarea = (mcuxClEcc_CpuWa_t *) mcuxClSession_getEndOfUsedBuffer_Internal(pSession);
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY()
    MCUX_CSSL_FP_FUNCTION_CALL(retCode_MontDH_SetupEnvironment, mcuxClEcc_MontDH_SetupEnvironment(pSession,
                                                                 pDomainParameters,
                                                                 ECC_MONTDH_NO_OF_BUFFERS));
    if(MCUXCLECC_STATUS_OK != retCode_MontDH_SetupEnvironment)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
    }

    /* Securely import private key d to PKC buffer ECC_S3 */
    const uint16_t * pOperands = MCUXCLPKC_GETUPTRT();
    uint8_t *pPrivateKeyDest = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S3]);
    MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_load));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_load(pSession,
                                                               key,
                                                               &pPrivateKeyDest,
                                                               MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
                                                               NULL,
                                                               MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                               MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE));

    /* Call mcuxClEcc_MontDH_X to calculate the public key q=MontDH_X(d,Gx) and store it in buffer MONT_X0. If the function returns NEUTRAL_POINT, return MCUXCLECC_STATUS_FAULT_ATTACK */
    uint8_t *pPublicKeyData = NULL;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_load));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_load(pSession,
                                                           pOtherKey,
                                                           &pPublicKeyData,
                                                           MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
                                                           NULL,
                                                           MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
                                                           MCUXCLKEY_ENCODING_SPEC_ACTION_PTR));

    MCUX_CSSL_FP_FUNCTION_CALL(retCode_MontDHx, mcuxClEcc_MontDH_X(pSession, pDomainParameters, (const uint8_t*)pPublicKeyData));

    if(MCUXCLECC_STATUS_RNG_ERROR == retCode_MontDHx)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_ERROR);
    }
    else if(MCUXCLECC_STATUS_OK != retCode_MontDHx)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLKEY_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Securely export shared secret from MONT_X0 */
        MCUXCLPKC_FP_SECUREEXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pOut, MONT_X0, keyLen);

        *pOutLength = keyLen;

        /* Import prime p and order n again, and check (compare with) existing one. */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_IntegrityCheckPN));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(
            mcuxClEcc_IntegrityCheckPN(pSession, (mcuxClEcc_CommonDomainParams_t *) &pDomainParameters->common));

        /* Return OK and exit */
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_MontDH_KeyAgreement,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_MontDH_SetupEnvironment),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_MontDH_X),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SecureExportLittleEndianFromPkc),
            MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
    }
}

const mcuxClKey_AgreementDescriptor_t mcuxClKey_AgreementDescriptor_MontDH =
{
    .pAgreementFct = mcuxClEcc_MontDH_KeyAgreement,
    .protectionTokenAgreementFct = MCUX_CSSL_FP_FUNCID_mcuxClEcc_MontDH_KeyAgreement,
    .pProtocolDescriptor = NULL
};
