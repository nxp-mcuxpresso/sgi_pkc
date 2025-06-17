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
 * @file  mcuxClEcc_WeierECC_Internal_EncTypeSEC.c
 * @brief ECC types and functions to perform point decoding of Weierstrass points encoded as specified in
 *        SEC 1: Elliptic Curve Cryptography
 */


#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClEcc.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClMath_Internal.h>

#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal_FP.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>


const mcuxClEcc_WeierECC_PointEncDescriptor_t mcuxClEcc_WeierECC_PointEncDescriptor_SEC =
{
    .pointDecFct = mcuxClEcc_WeierECC_PointDecFct_SEC,
    .pointDecFctFPId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_PointDecFct_SEC)
};

/**
 * This function implements the point decoding according to SEC 1: Elliptic Curve Cryptography.
 * Given an encoded point byte string starting with
 *  - 0x00 (neutral point case), the function returns MCUXCLECC_STATUS_NEUTRAL_POINT
 *  - 0x02 or 0x03 (compressed point case), the byte string is considered a compressed point,
 *    the function decompresses it and returns the decoded point (x,y) as x || y.
 *  - 0x04 (uncompressed point case), the function parses the byte string as 0x04 || x || y and returns the decoded point (x,y) as x || y.
 *
 * Inputs:
 *  - pSession                 Handle for the current CL session.
 *  - pEncodedPoint            Pointer to buffer containing the encoded point. The size of the buffer depends on the encoding variant.
 *  - pointEncType             Point encoding type specifying all information needed about the applied point encoding format.
 *  - pEccWeierDomainParams    Pointer to short Weierstrass curve custom parameters.
 *
 * Prerequisites:
 *   None
 *
 * Result:
 *  - If the function returns MCUXCLECC_STATUS_OK, the decoded point is written to pDecodedPoint.
 *
 * Returns:
 *  - MCUXCLECC_STATUS_OK                if the decoding was successful
 *  - MCUXCLECC_STATUS_NEUTRAL_POINT     if the encoded point starts with 0x00
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_WeierECC_PointDecFct_SEC, mcuxClEcc_WeierECC_PointDecodingFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_WeierECC_PointDecFct_SEC(
    mcuxClSession_Handle_t pSession,
    mcuxCl_InputBuffer_t pEncodedPoint,
    mcuxCl_Buffer_t pDecodedPoint,
    mcuxClEcc_WeierECC_PointEncType_t pointEncType,
    mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_WeierECC_PointDecFct_SEC,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read) );

    (void) pointEncType;

    uint8_t encodingByte;
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pEncodedPoint);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, &encodingByte);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, 1u);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pEncodedPoint, 0u, &encodingByte, 1u));

    const uint32_t byteLenP = pEccWeierDomainParams->common.byteLenP;

    if(0x00u == encodingByte)
    {
        /* Neutral point */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_WeierECC_PointDecFct_SEC, MCUXCLECC_STATUS_NEUTRAL_POINT);
    }
    else if((0x02u == encodingByte) || (0x03u == encodingByte))
    {
        /* Compressed point */

        /**********************************************************************/
        /* Setup environment                                                  */
        /**********************************************************************/

        MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - mcuxClEcc_CpuWa_t is 32 bit aligned")
        mcuxClEcc_CpuWa_t *pCpuWorkarea = (mcuxClEcc_CpuWa_t *) mcuxClSession_getEndOfUsedBuffer_Internal(pSession);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_WeierECC_SetupEnvironment(pSession,
                                        pEccWeierDomainParams,
                                        ECC_DECODEPOINT_NO_OF_BUFFERS));

        uint16_t *pOperands = MCUXCLPKC_GETUPTRT();

        /**********************************************************************/
        /* Compute alpha = x^3 + ax + b mod p, store alpha in ECC_S1          */
        /**********************************************************************/

        MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND(); /* avoid CPU accessing PKC workarea when PKC is busy */

        /* Import the encoded x coordinate to buffer WEIER_XA */
        const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
        MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFEROFFSET_DI_BALANCED(mcuxClEcc_WeierECC_PointDecFct_SEC, WEIER_XA, pEncodedPoint, 1u, byteLenP, operandSize);

        pOperands[WEIER_VX0] = (uint16_t) 0x02u;
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_DecodePoint_SEC_CalcAlpha,
                            mcuxClEcc_FUP_DecodePoint_SEC_CalcAlpha_LEN);

        /**********************************************************************/
        /* Compute the square root beta of alpha, store beta in ECC_S2.       */
        /**********************************************************************/
        MCUXCLMATH_FP_MODSQUAREROOT(ECC_S2    /* beta */,
                                   ECC_S1    /* alpha */,
                                   ECC_P     /* prime p */,
                                   ECC_PQSQR /* Montgomery parameter R^2 (mod p) */,
                                   ECC_T0    /* tmp */,
                                   ECC_S0    /* tmp */,
                                   ECC_T1    /* tmp */,
                                   ECC_T2    /* tmp */,
                                   byteLenP);

        /**********************************************************************/
        /* Verify that beta^2 = alpha mod p holds, to verify the point.       */
        /* Store beta in range [0, p-1] in NR in WEIER_YA                     */
        /**********************************************************************/

        /* Calculate beta^2-alpha, and beta in range [0, p-1] in NR will be stored in WEIER_YA */
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_DecodePoint_SEC_VerifyBeta,
                            mcuxClEcc_FUP_DecodePoint_SEC_VerifyBeta_LEN);

        /* Check zero-flag to validate the comparisson */
        if(MCUXCLPKC_FLAG_NONZERO == MCUXCLPKC_WAITFORFINISH_GETZERO())
        {
            /* beta^2 = alpha mod p does not hold */
            mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
            MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

            mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

            MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
        }

        /**********************************************************************/
        /* If LSbit(beta) == LSbit(y) set y = beta, else set y = p-beta.      */
        /* Export the point.                                                  */
        /**********************************************************************/

        if((encodingByte & 0x01u) != (MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_YA])[0] & 0x01u))
        {
            MCUXCLPKC_FP_CALC_OP1_SUB(WEIER_YA, ECC_P, WEIER_YA);
            /* Balance FP before operand WEIER_YA is destroyed. */
            MCUX_CSSL_FP_EXPECT(MCUXCLPKC_FP_CALLED_CALC_OP1_SUB);
        }

        /* Success - Export decoded point */
        MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFER_DI_BALANCED(mcuxClEcc_WeierECC_PointDecFct_SEC, pDecodedPoint, WEIER_XA, byteLenP);
        MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFEROFFSET_DI_BALANCED(mcuxClEcc_WeierECC_PointDecFct_SEC, pDecodedPoint, WEIER_YA, byteLenP, byteLenP);

        /* Clean-up */
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_WeierECC_PointDecFct_SEC,
                                  MCUXCLECC_STATUS_OK,
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_SetupEnvironment),
                                  MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFEROFFSET,
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModSquareRoot),
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
                                  MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFER,
                                  MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFEROFFSET,
                                  MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
    }
    else if(0x04u == encodingByte)
    {
        /* Uncompressed point */

        MCUXCLPKC_FP_REQUEST_INITIALIZE(pSession, mcuxClEcc_WeierECC_PointDecFct_SEC);
        const uint32_t pkcWaSizeInCpuWords = MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(2u * byteLenP);
        uint8_t *pPkcWa = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, pkcWaSizeInCpuWords);

        /* Copy out decompressed point (x, y) as x || y (strip the first byte of the encoding) */
        MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pEncodedPoint);
        MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, 1u);
        MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pPkcWa);
        MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, 2u * byteLenP);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pEncodedPoint, 1u, pPkcWa, 2u * byteLenP));

        MCUX_CSSL_DI_RECORD(mcuxClBuffer_write, pDecodedPoint);
        MCUX_CSSL_DI_RECORD(mcuxClBuffer_write, pPkcWa);
        MCUX_CSSL_DI_RECORD(mcuxClBuffer_write, 2u * byteLenP);
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(pDecodedPoint, 0u, pPkcWa, 2u * byteLenP));

        mcuxClSession_freeWords_pkcWa(pSession, pkcWaSizeInCpuWords);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_WeierECC_PointDecFct_SEC,
                                  MCUXCLECC_STATUS_OK,
                                  MCUXCLPKC_FP_CALLED_REQUEST_INITIALIZE,
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write),
                                  MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
    }
    else
    {
        /* Invalid encoding */
        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_UNREACHABLE_CODE("Unreachable code is allowed for fault attack protection.")
    MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_UNREACHABLE_CODE()
}
