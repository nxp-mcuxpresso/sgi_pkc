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
 * @file  mcuxClEcc_EdDSA_VerifySignature.c
 * @brief Implementation of the EdDSA signature verification functionality
 */

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslParamIntegrity.h>

#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClKey.h>
#include <mcuxClEcc.h>
#include <mcuxClHash.h>
#include <mcuxClSignature.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClEcc_Internal_KeyHelper.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClSignature_Internal.h>
#include <internal/mcuxClEcc_Internal_FUP.h>
#include <internal/mcuxClEcc_TwEd_Internal.h>
#include <internal/mcuxClEcc_TwEd_Internal_FUP.h>
#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal_FUP.h>

/**
 * This function verifies that the signature component S satisfies S < n and in this case performs the scalar multiplication
 * h * S * G of S with the EdDSA base point as part of the EdDSA signature verification process.
 *
 * Input:
 *  - pSession [in]         Handle for the current CL session
 *  - pDomainParams [in]    Pointer to EdDSA domain parameters
 *  - pSignature [in]       Buffer for the signature (Renc,S)
 *  - bitLenN [in]          Bit length of the base point order n
 *
 * Prerequisites:
 *  - ps1Len = (operandSize, operandSize)
 *  - Buffers ECC_CP0 and ECC_CP1 contain the curve parameters a and d in MR
 *  - Buffer ECC_PFULL contains p'||p
 *  - Buffer ECC_PS contains the shifted modulus associated to p
 *
 * Result:
 *  - If the function returned OK, then the result of the scalar multiplication h * S * G is stored
 *    in homogeneous coordinates in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
 *    NOTE: This also holds for the neutral point result in case S = 0.
 *
 * Returns:
 *  - MCUXCLECC_STATUS_OK                    if the function executed successfully
 *  - MCUXCLECC_STATUS_INVALID_SIGNATURE     if S does not satisfy S < n, i.e. the signature is invalid
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_VerifySignature_BasePointScalarMult)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_EdDSA_VerifySignature_BasePointScalarMult(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_EdDSA_DomainParams_t *pDomainParams,
    mcuxCl_InputBuffer_t pSignature,
    uint32_t bitLenN)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_VerifySignature_BasePointScalarMult);

    const uint32_t encodedLen = (uint32_t)pDomainParams->b / 8u;
    const uint32_t encodedAlignedLen = MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(encodedLen);

    /*
     * Step 1: Import signature component S to buffer ECC_S0 and check if it is smaller than n.
     */

    /* Import S to ECC_S0 */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFEROFFSET);
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_BUFFEROFFSET_DI_BALANCED(mcuxClEcc_EdDSA_VerifySignature_BasePointScalarMult,
                                                                 ECC_S0,
                                                                 pSignature,
                                                                 encodedLen,
                                                                 encodedLen,
                                                                 encodedAlignedLen);

    /* Check s < n. */
    MCUXCLPKC_PS2_SETLENGTH(0u, encodedAlignedLen);
    /* Copy N to T1 with MSbits set to 0 */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP2_CONST);
    MCUXCLPKC_FP_CALC_OP2_CONST(ECC_T1, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_T1, ECC_N, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP2_CMP);
    MCUXCLPKC_FP_CALC_OP2_CMP(ECC_S0, ECC_T1);
    if (MCUXCLPKC_FLAG_NOCARRY == MCUXCLPKC_WAITFORFINISH_GETCARRY())
    {   /* s >= n. */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature_BasePointScalarMult, MCUXCLECC_STATUS_INVALID_SIGNATURE);
    }

    /*
     * Step 2: Calculate P1' = S * G, and store the result in homogeneous coordinates (X:Y:Z) in MR in buffers
     *         ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     */

    /* Calculate P1' = S * G
     *
     * NOTE: In case S = 0, the neutral point is correctly computed by the function and stored as (0:Z:Z). */
    MCUX_CSSL_DI_RECORD(plainFixScalarMult, MCUXCLECC_SCALARMULT_OPTION_PLAIN * bitLenN);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        pDomainParams->common.pScalarMultFunctions->plainFixScalarMultFct(
            pSession,
            (mcuxClEcc_CommonDomainParams_t *)&pDomainParams->common,
            ECC_S0,
            bitLenN,
            MCUXCLECC_SCALARMULT_OPTION_AFFINE_INPUT |
            MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_OUTPUT |
            MCUXCLECC_SCALARMULT_OPTION_NO_OUTPUT_VALIDATION));

    /*
     * Step 3: Calculate P1 = h * P1' = h * S * G using repeated point doubling, and store the result in homogeneous
     *          coordinates (X:Y:Z) in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     *
     * NOTE: c = cofactor exponent, i.e. cofactor: h = 2^c.
     */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_TwEd_RepeatedDoubling));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_TwEd_RepeatedDoubling(pDomainParams->c));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature_BasePointScalarMult, MCUXCLECC_STATUS_OK,
        pDomainParams->common.pScalarMultFunctions->plainFixScalarMultFctFPId);
}

/**
 * This function computes the value H(prefix||Renc||Qenc||m') mod n, decodes the public EdDSA key Qenc and performs the scalar multiplication
 * h * H(prefix||Renc||Qenc||m') * Q = (H(prefix||Renc||Qenc||m') mod n) * h * Q with the decoded EdDSA public key Q as part of the
 * EdDSA signature verification process.
 *
 * Input:
 *  - pSession [in]         Handle for the current CL session
 *  - pubKey [in]           Key handle for public key Qenc
 *  - signatureMode [in]    Mode descriptor specifying the EdDSA variant
 *  - pIn [in]              Buffer for message digest m'
 *  - inSize [in]           Size of message digest m'
 *  - pCpuWorkarea [in]     Pointer to ECC specific CPU workarea struct
 *  - pDomainParams [in]    Pointer to EdDSA domain parameters
 *  - buffSignatureR [in]   Buffer containing the EdDSA signature component Renc
 *  - bitLenN [in]          Bit length of the base point order n
 *
 * Prerequisites:
 *  - ps1Len = (operandSize, operandSize)
 *  - Buffers ECC_CP0 and ECC_CP1 contain the curve parameters a and d in MR
 *  - Buffer ECC_PFULL contains p'||p
 *  - Buffer ECC_PS contains the shifted modulus associated to p
 *
 * Result:
 *  - If the function returned OK, then the result of the scalar multiplication h * H(prefix||Renc||Qenc||m') * Q is stored
 *    in homogeneous coordinates in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_VerifySignature_PubKeyScalarMult)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_EdDSA_VerifySignature_PubKeyScalarMult(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t pubKey,
    mcuxClSignature_Mode_t signatureMode,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inSize,
    mcuxClEcc_CpuWa_t * const pCpuWorkarea,
    mcuxClEcc_EdDSA_DomainParams_t *pDomainParams,
    mcuxCl_InputBuffer_t buffSignatureR,
    uint32_t bitLenN)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_VerifySignature_PubKeyScalarMult);

    const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *mode = (const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *)signatureMode->pProtocolDescriptor;

    /*
     * Step 1: Derive the hash prefix from the mode parameter and calculate H(prefix||Renc||Qenc||m') mod n
     * and store it in buffer ECC_S2.
     */

    /* Load the encoded public key to buffer ECC_COORD00.
     *
     * NOTE: The point decoding function called below requires the encoded public key to be in ECC_COORD00. */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    uint8_t *pPubKey = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_COORD00]);
    MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(pubKey));
    MCUXCLKEY_LOAD_FP(
      pSession,
      pubKey,
      &pPubKey,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
      NULL,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
      MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL);

    /* Generate digest m' from m in case phflag is set */
    const uint8_t *m = NULL;
    uint32_t mLen = 0u;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_PreHashMessage));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_EdDSA_PreHashMessage(pSession, pDomainParams, pCpuWorkarea, mode->phflag, pIn, inSize, &m, &mLen));

    MCUXCLBUFFER_INIT_RO(buffM1, NULL, m, mLen);
    mcuxCl_InputBuffer_t buffM = NULL;
    if (MCUXCLECC_EDDSA_PHFLAG_ONE == mode->phflag)
    {
        buffM = buffM1;
    }
    else if (MCUXCLECC_EDDSA_PHFLAG_ZERO == mode->phflag)
    {
        buffM = pIn;
    }
    else
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_CalcHashModN));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_EdDSA_CalcHashModN(
                                  pSession, pDomainParams,
                                  mode->pHashPrefix, mode->hashPrefixLen,
                                  buffSignatureR,
                                  pubKey,
                                  buffM, mLen));

    /*
     * Step 2: Call function pDomainParams->pDecodePointFct to decode the public key Qenc and store
     * the homogeneous coordinates of the decoded point Q in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     */

    /* NOTE: The public key has been loaded above into buffer ECC_COORD00. */
    MCUXCLPKC_WAITFORFINISH(); // TODO CLNS-16936: investigate if this can be removed because of MCUXCL_FEATURE_PKC_CPUPKC_ARBITRATION_WORKAROUND in mcuxClEcc_EdDSA_CalcHashModN
    MCUX_CSSL_FP_FUNCTION_CALL(ret_decodePoint,
        pDomainParams->pDecodePointFct(
            pSession, pDomainParams) );
    if(MCUXCLECC_INTSTATUS_DECODING_NOT_OK == ret_decodePoint)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
    }
    else if (MCUXCLECC_STATUS_OK != ret_decodePoint)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Intentionally left empty */
    }

    /*
     * Step 3: Calculate P2' = h * Q using repeated point doubling, and store the result in homogeneous
     *         coordinates (X:Y:Z) in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     *
     * NOTE: c = cofactor exponent, i.e. cofactor: h = 2^c.
     */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_TwEd_RepeatedDoubling(pDomainParams->c));

    /*
     * Step 4: Call function pDomainParameters->pPlainVarScalarMultFct to calculate
     *           P2 = (H(prefix||Renc||Qenc||m') mod n) * P2'
     *              = h * H(prefix||Renc||Qenc||m') * Q
     *         and store the result in homogeneous coordinates in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     *
     * NOTES:
     *  - Due to the scalar multiplication by the cofactor h above, P2' is ensured to be in the base point order group
     *    of order n. Therefore, the variable scalar multiplication function, which only works for points for input points
     *    in this group, can be used.
     *  - Since the input point P2' has order dividing n, it's fine to use the scalar (H(prefix||Renc||Qenc||m') mod n) instead
     *    of H(prefix||Renc||Qenc||m'). Note that this would not have been the case for the public key which might be a point
     *    of even order such that (H(prefix||Renc||Qenc||m') mod n) * Q is not necessarily the same as H(prefix||Renc||Qenc||m') * Q.
     *  - If either the scalar is zero mod n or P2' is the neutal point, the resulting neutral point is correctly returned in buffers
     *    ECC_COORD00, ECC_COORD01 and ECC_COORD02 by the function.
     */

    MCUX_CSSL_DI_RECORD(plainVarScalarMult, MCUXCLECC_SCALARMULT_OPTION_PLAIN * bitLenN);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        pDomainParams->common.pScalarMultFunctions->plainVarScalarMultFct(
            pSession,
            &pDomainParams->common,
            ECC_S2,
            bitLenN,
            MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_INPUT |
            MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_OUTPUT |
            MCUXCLECC_SCALARMULT_OPTION_NO_OUTPUT_VALIDATION));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_EdDSA_VerifySignature_PubKeyScalarMult,
        pDomainParams->pDecodePoint_FP_FuncId /* Step 2 */,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_TwEd_RepeatedDoubling) /* Step 3 */,
        pDomainParams->common.pScalarMultFunctions->plainVarScalarMultFctFPId /* Step 4 */);
}

/**
 * This function verifies the EdDSA signature equation
 *
 *     (h * G) * B = h * R + (h * H(prefix||Renc||Qenc||m')) * Q
 *
 * by first decoding the signature component Renc and returning #MCUXCLECC_STATUS_INVALID_SIGNATURE if the decoding fails.
 * It then computes h * R and compares it against the previously computed point h * R', where R' = S * G - H(prefix||Renc||Qenc||m') * Q.
 * If the comparison fails, #MCUXCLECC_STATUS_INVALID_SIGNATURE is returned. Otherwise, #MCUXCLECC_STATUS_OK is returned.
 *
 * The point comparison is performed by the PKC and the PKC ZERO flag after the comparison is stored in the variable
 * zeroFlagValidityCheckByPKC passed to this function via pointer to facilitate integrity checking of the signature check in the calling function.
 *
 * Input:
 *  - pSession [in]                     Handle for the current CL session
 *  - pDomainParams [in]                Pointer to EdDSA domain parameters
 *  - buffSignatureR [in]               Buffer containing the (encoded) input signature component Renc
 *  - pZeroFlagValidityCheckByPKC [in]  Pointer to target variable to store the PKC ZERO flag of the signature equation comparison in
 *
 * Result:
 *  - If the signature equation check
 *    - passed, then zeroFlagValidityCheckByPKC equals MCUXCLPKC_FLAG_ZERO
 *    - failed, then zeroFlagValidityCheckByPKC equals MCUXCLPKC_FLAG_NONZERO
 *
 * Returns:
 *  - MCUXCLECC_STATUS_OK                    if the signature equation check passed
 *  - MCUXCLECC_STATUS_INVALID_SIGNATURE     if the signature equation check failed
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_CheckSignatureEquation)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_EdDSA_CheckSignatureEquation(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_EdDSA_DomainParams_t *pDomainParams,
    mcuxCl_InputBuffer_t buffSignatureR,
    volatile uint32_t *pZeroFlagValidityCheckByPKC)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_CheckSignatureEquation);

    const uint32_t encodedLen = (uint32_t)pDomainParams->b / 8u;
    const uint32_t encodedAlignedLen = MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(encodedLen);

    /*
     * Step 1: Call function pDomainParams->pDecodePointFct to decode Renc and store the homogeneous
     *         coordinates of the decoded point R in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     *         If the decoding fails, return #MCUXCLECC_STATUS_INVALID_SIGNATURE.
     */

    /* Import Renc to ECC_COORD00 */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER);
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_EdDSA_CheckSignatureEquation,
                                                           ECC_COORD00, buffSignatureR, encodedLen, encodedAlignedLen);

    /* Decode Renc */
    MCUX_CSSL_FP_EXPECT(pDomainParams->pDecodePoint_FP_FuncId);
    MCUX_CSSL_FP_FUNCTION_CALL(ret2_decodePoint,
                              pDomainParams->pDecodePointFct(
                                  pSession,
                                  pDomainParams));
    if (MCUXCLECC_INTSTATUS_DECODING_NOT_OK == ret2_decodePoint)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_CheckSignatureEquation, MCUXCLECC_STATUS_INVALID_SIGNATURE);
    }
    else if (MCUXCLECC_STATUS_OK != ret2_decodePoint)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Intentionally left empty */
    }

    /*
     * Step 2: Calculate h*R using repeated point doubling, and store the result in homogeneous
     *         coordinates (X:Y:Z) in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_TwEd_RepeatedDoubling));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_TwEd_RepeatedDoubling(pDomainParams->c));

    /*
     * Step 3: Before finally comparing h*R = (X:Y:Z) with h*R' = (X':Y':Z'), perform a sanity check on the Z-coordinates.
     *         Since both h*R and h*R' are valid points on the curve derived from finite points via complete curve
     *         arithmetic formulas arithmetic, they must also be finite, since for Ed25519 and Ed448
     *         the curve parameter d is a non-square modulo p.
     *         Hence, if one of the two Z-coordinates is zero mod p, FAULT_ATTACK is returned.
     */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_MC1_MM);
    MCUXCLPKC_FP_CALC_MC1_MM(ECC_T0, ECC_COORD02, ECC_COORD27, ECC_P); // = Z*Z' in MR
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_MC1_MR);
    MCUXCLPKC_FP_CALC_MC1_MR(ECC_T1, ECC_T0, ECC_P); // = Z*Z' in NR in range [0,p]
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_MC1_MS);
    MCUXCLPKC_FP_CALC_MC1_MS(ECC_T0, ECC_T1, ECC_P, ECC_P); // = Z*Z' mod p
    if(MCUXCLPKC_FLAG_ZERO == MCUXCLPKC_WAITFORFINISH_GETZERO())
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    /*
     * Step 4: Bring h*R' and h*R to the same Z-coordinate and compare the coordinates.
     *         If the points are not equal, return #MCUXCLECC_STATUS_INVALID_SIGNATURE.
     */

    /* The coordinates of h*R' are passed via ECC_V0, ECC_V1, ECC_V2 to the point comparison below. */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    pOperands[ECC_V0] = pOperands[ECC_COORD25];
    pOperands[ECC_V1] = pOperands[ECC_COORD26];
    pOperands[ECC_V2] = pOperands[ECC_COORD27];

    /* Run the point comparison of P1 = h*R = (X1:Y1:Z1) and P2 = h*R' = (X2:Y2:Z2). The FUP program expects
     *  - the coordinates of h*R (point P1) to be passed via ECC_V0, ECC_V1, ECC_V2.
     *  - the coordinates of h*R' (point P2) to be stored in buffers ECC_COORD00, ECC_COORD01, ECC_COORD02.
     * As a result of the FUP program
     *  - the ZERO flag is set if and only if the PKC comparison of the two points passed
     *  - buffers ECC_S0 and ECC_S1 contain the concatenations X1' || Y1' and X2' || Y2', respectively, where
     *      - (X1':Y1':Z1') = (X1*Z2:Y1*Z2:Z1*Z2) are updated coordinates of P1 and
     *      - (X2':Y2':Z2') = (X2*Z1:Y2*Z1:Z2*Z1) are updated coordinates for P2
     *    sharing the same Z-coordinate for a potential upcoming double comparison by the CPU. */
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("the result of *pOperands + (uint16_t) operandSize is in range of uint16")
    pOperands[ECC_V3] = pOperands[ECC_S0] + (uint16_t)operandSize;
    pOperands[ECC_V4] = pOperands[ECC_S1] + (uint16_t)operandSize;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_PointComparisonHom,
                        mcuxClEcc_FUP_PointComparisonHom_LEN);
    *pZeroFlagValidityCheckByPKC = MCUXCLPKC_WAITFORFINISH_GETZERO();

    /* Check if the EdDSA signature verification passed or failed. */
    if (MCUXCLPKC_FLAG_ZERO == *pZeroFlagValidityCheckByPKC)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_CheckSignatureEquation, MCUXCLECC_STATUS_OK);
    }
    else if (MCUXCLPKC_FLAG_NONZERO == *pZeroFlagValidityCheckByPKC)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_CheckSignatureEquation, MCUXCLECC_STATUS_INVALID_SIGNATURE);
    }
    else
    {
        /* When PKC comparison of h*Renc and (h*R')enc returned neither ZERO nor NONZERO, return FAULT_ATTACK. */
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_VerifySignature, mcuxClSignature_VerifyFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClEcc_EdDSA_VerifySignature(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key,
    mcuxClSignature_Mode_t signatureMode,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inSize,
    mcuxCl_InputBuffer_t pSignature,
    uint32_t signatureSize )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_VerifySignature);

    /*
     * Step 1: Verify that the passed signatureSize value is as expected.
     */

    mcuxClEcc_EdDSA_DomainParams_t * const pDomainParams = (mcuxClEcc_EdDSA_DomainParams_t *) mcuxClKey_getTypeInfo(key);
    const uint32_t encodedLen = (uint32_t) pDomainParams->b / 8u;
    const uint32_t sigLength = encodedLen * 2u;

    if (signatureSize != sigLength)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLSIGNATURE_STATUS_INVALID_PARAMS);
    }

    /*
     * Step 2: Set up the environment
     */

    /* mcuxClEcc_CpuWa_t will be allocated and placed in the beginning of CPU workarea free space by SetupEnvironment. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - re-interpreting the memory")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
    MCUX_CSSL_FP_FUNCTION_CALL(mcuxClEcc_CpuWa_t*, pCpuWorkarea, mcuxClSession_allocateWords_cpuWa(pSession, 0u));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_SetupEnvironment));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_EdDSA_SetupEnvironment(pSession, pDomainParams, ECC_EDDSA_NO_OF_BUFFERS) );

    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();

    /*
     * Step 3: Import signature component S and check if S < n holds. If not, return INVALID_SIGNATURE. Otherwise, calculate
     *         P1 = h * S * G, and store the result in homogeneous coordinates in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     *         In case S = 0, the neutral point is also correctly computed by the function.
     */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_LeadingZeros));
    MCUX_CSSL_FP_FUNCTION_CALL(leadingZerosN, mcuxClMath_LeadingZeros(ECC_N));

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(leadingZerosN, 0U, 8U * MCUXCLPKC_WORDSIZE, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(operandSize, 32U /* for Ed25519 */, 56U /* for Ed448 */, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
    uint32_t bitLenN = (operandSize * 8u) - leadingZerosN;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_VerifySignature_BasePointScalarMult));
    MCUX_CSSL_FP_FUNCTION_CALL(retBasePointScalarMult,
        mcuxClEcc_EdDSA_VerifySignature_BasePointScalarMult(pSession, pDomainParams, pSignature, bitLenN) );
    if (MCUXCLECC_STATUS_INVALID_SIGNATURE == retBasePointScalarMult)
    {   /* s >= n. */
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_DI_RECORD(mcuxClEcc_EdDSA_VerifySignature_return, MCUXCLSIGNATURE_STATUS_NOT_OK);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLSIGNATURE_STATUS_NOT_OK);
    }
    else if (MCUXCLECC_STATUS_OK != retBasePointScalarMult)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Intentionally left empty */
    }

    /*
     * Step 4: Back up the coordinates of P1 in buffers ECC_COORD25, ECC_COORD26 and ECC_COORD27.
     */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD25, ECC_COORD00, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD26, ECC_COORD01, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD27, ECC_COORD02, 0u);

    /*
     * Step 5: Computes the value H(prefix||Renc||Qenc||m') mod n, decode the public EdDSA key Qenc and perform the scalar multiplication
     *         P2 = h * H(prefix||Renc||Qenc||m') * Q = (H(prefix||Renc||Qenc||m') mod n) * (h * Q) with the decoded EdDSA public key Q
     *         and store the result in homogeneous coordinates in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     *         Even if the scalar is zero mod n or the public key is the neutral point or of even order, the result is correctly computed.
     *         If the public key decoding fails, i.e. when the corresponding point is not on the curve, INVALID_PARAMS will be returned.
     */
    const mcuxCl_InputBuffer_t buffSignatureR = pSignature;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_VerifySignature_PubKeyScalarMult));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_EdDSA_VerifySignature_PubKeyScalarMult(pSession,
                                                                              key,
                                                                              signatureMode,
                                                                              pIn,
                                                                              inSize,
                                                                              pCpuWorkarea,
                                                                              pDomainParams,
                                                                              buffSignatureR,
                                                                              bitLenN) );

    /*
     * Step 6: Calculate h * R' = P1-P2, check that it lies on the curve and store the homogeneous coordinates of R' in the buffers
     *         ECC_COORD25, ECC_COORD26 and ECC_COORD27.
     */

    /* Compute h * R' = P1 - P2
     *
     * NOTE: A complete subtraction algorithm is used, so for valid input points, the resulting point is correctly computed. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_TwEd_PointSubtraction, mcuxClEcc_FUP_TwEd_PointSubtraction_LEN);

    /* Verify that h * R' lies on the curve */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_TwEd_PointValidation_HomMR, mcuxClEcc_FUP_TwEd_PointValidation_HomMR_LEN);
    if (MCUXCLPKC_FLAG_ZERO != MCUXCLPKC_WAITFORFINISH_GETZERO())
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
    }

    /* Backup h*R' */
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD25, ECC_COORD00, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD26, ECC_COORD01, 0u);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD27, ECC_COORD02, 0u);

    /*
     * Step 7: Perform the final EdDSA signature verification step.
     */

    /* Initialize variable to store the PKC comparison result of the EdDSA signature verification for later integrity checking of the verification result.
     * The verification as well as the setting of the variable is done inside mcuxClEcc_EdDSA_CheckSignatureEquation. */
    volatile uint32_t zeroFlagValidityCheckByPKC = MCUXCLPKC_FLAG_NONZERO;

    /* Check the EdDSA signature equation. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_CheckSignatureEquation));
    MCUX_CSSL_FP_FUNCTION_CALL(ret_CheckSignatureEquation,
                              mcuxClEcc_EdDSA_CheckSignatureEquation(pSession, pDomainParams, buffSignatureR, &zeroFlagValidityCheckByPKC));
    if (MCUXCLECC_STATUS_INVALID_SIGNATURE == ret_CheckSignatureEquation)
    {
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_DI_RECORD(mcuxClEcc_EdDSA_VerifySignature_return, MCUXCLSIGNATURE_STATUS_NOT_OK);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLSIGNATURE_STATUS_NOT_OK);
    }
    else if (MCUXCLECC_STATUS_OK != ret_CheckSignatureEquation)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Intentionally left empty */
    }

    /*
     * Step 8: Return #MCUXCLSIGNATURE_STATUS_OK.
     */

    /* Import prime p and order n again, and check (compare with) existing one. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_IntegrityCheckPN));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        mcuxClEcc_IntegrityCheckPN(pSession, (mcuxClEcc_CommonDomainParams_t *) &pDomainParams->common));

    /* Clean up and exit */
    mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
    MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
    MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

    mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

    MCUX_CSSL_DI_RECORD(mcuxClEcc_EdDSA_VerifySignature_return, MCUXCLSIGNATURE_STATUS_OK);
    uint32_t retCode = (MCUXCLSIGNATURE_STATUS_OK ^ MCUXCLPKC_FLAG_ZERO) ^ zeroFlagValidityCheckByPKC;
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature,
                                retCode);
}
