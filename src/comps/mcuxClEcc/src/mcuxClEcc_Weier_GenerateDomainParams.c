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
 * @file  mcuxClEcc_Weier_GenerateDomainParams.c
 * @brief ECC Weierstrass custom domain parameter generation function
 */


#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClEcc.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClMath_Internal.h>

#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal_FP.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_WeierECC_GenerateDomainParams)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_WeierECC_GenerateDomainParams(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams,
    mcuxClEcc_Weier_BasicDomainParams_t *pEccWeierBasicDomainParams,
    uint32_t options)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClEcc_WeierECC_GenerateDomainParams, diRefValue, MCUXCLECC_STATUS_FAULT_ATTACK);

    /**********************************************************/
    /* Initialization and parameter verification              */
    /**********************************************************/

    const uint32_t byteLenP = pEccWeierBasicDomainParams->pLen;
    const uint32_t byteLenN = pEccWeierBasicDomainParams->nLen;
    const uint32_t byteLenMax = ((byteLenP > byteLenN) ? byteLenP : byteLenN);
    const uint32_t operandSize = MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(byteLenMax);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("The result does not wrap. The bufferSize can't be larger than UINT32_MAX.")
    const uint32_t bufferSize = operandSize + MCUXCLPKC_WORDSIZE;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    /* Setup CPU workarea and PKC buffer. */
    const uint32_t byteLenOperandsTable = (sizeof(uint16_t)) * (ECC_NO_OF_VIRTUALS + ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS);
    const uint32_t alignedByteLenCpuWa = MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_CpuWa_t)) + sizeof(uint32_t) /* Reserve 1 word for making UPTR table start from 64-bit aligned address */
                                          + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(byteLenOperandsTable);
    const uint32_t wordNumCpuWa = alignedByteLenCpuWa / (sizeof(uint32_t));
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - mcuxClEcc_CpuWa_t is 32 bit aligned")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
    MCUX_CSSL_FP_FUNCTION_CALL(mcuxClEcc_CpuWa_t*, pCpuWorkarea, mcuxClSession_allocateWords_cpuWa(pSession, wordNumCpuWa));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("The result does not wrap. The bufferSize * 22U can't be larger than UINT32_MAX.")
    const uint32_t wordNumPkcWa = (bufferSize * ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) / (sizeof(uint32_t));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
    MCUX_CSSL_FP_FUNCTION_CALL(const uint8_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(pSession, wordNumPkcWa));

    pCpuWorkarea->wordNumCpuWa = wordNumCpuWa;
    pCpuWorkarea->wordNumPkcWa = wordNumPkcWa;

    MCUXCLPKC_FP_REQUEST_INITIALIZE(pSession, mcuxClEcc_WeierECC_GenerateDomainParams);

    /* Set PS1 MCLEN and LEN. */
    MCUXCLPKC_PS1_SETLENGTH(operandSize, operandSize);

    /* Setup uptr table. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("16-bit UPTRT table is assigned in CPU workarea")
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("Arithmetic to align pointers on 2 bytes")
    uint16_t *pOperands = (uint16_t *)MCUXCLCORE_ALIGN_TO_WORDSIZE(sizeof(uint64_t), (uint32_t)pCpuWorkarea + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_CpuWa_t))); /* Make UPTR table start from 64-bit aligned address */
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()
    MCUXCLPKC_FP_GENERATEUPTRT(& pOperands[ECC_GENERATEDOMAINPARAMS_NO_OF_VIRTUALS],
                              pPkcWorkarea,
                              (uint16_t) bufferSize,
                              ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS);
    MCUXCLPKC_SETUPTRT(pOperands);

    /* Setup virtual offsets to prime p and curve order n. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("the result is in range of uint16");
    pOperands[ECC_P] = (uint16_t) (pOperands[ECC_PFULL] + MCUXCLPKC_WORDSIZE);
    pOperands[ECC_N] = (uint16_t) (pOperands[ECC_NFULL] + MCUXCLPKC_WORDSIZE);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA();

    /* Initialize constants ONE = 0x0001 and ZERO = 0x0000 in uptr table. */
    pOperands[ECC_ONE]  = 0x0001u;
    pOperands[ECC_ZERO] = 0x0000u;


    /**********************************************************/
    /* Import / prepare curve parameters                      */
    /**********************************************************/

    /* Import prime p and order n. */
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_WeierECC_GenerateDomainParams, ECC_P, pEccWeierBasicDomainParams->pP, byteLenP, operandSize);
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_WeierECC_GenerateDomainParams, ECC_N, pEccWeierBasicDomainParams->pN, byteLenN, operandSize);

    /* Check p and n are odd (Math functions assume modulus is odd). */
    const volatile uint8_t * ptrP = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_P]);
    const volatile uint8_t * ptrN = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_N]);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("PKC buffer is CPU word aligned")
    uint32_t p0 = ((const volatile uint32_t *) ptrP)[0];
    uint32_t n0 = ((const volatile uint32_t *) ptrN)[0];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    if (0x01u != (0x01u & p0 & n0))
    {
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
    }

    /* Calculate NDash of p and n, ShiftModulus of p and n, QSquared of p. */
    MCUXCLMATH_FP_NDASH(ECC_P, ECC_T0);
    MCUXCLMATH_FP_NDASH(ECC_N, ECC_T0);
    MCUXCLMATH_FP_SHIFTMODULUS(ECC_PS, ECC_P);
    MCUXCLMATH_FP_SHIFTMODULUS(ECC_NS, ECC_N);
    MCUXCLMATH_FP_QSQUARED(ECC_PQSQR, ECC_PS, ECC_P, ECC_T0);

    /* Import coefficients a and b, and convert a to MR. */
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_WeierECC_GenerateDomainParams, ECC_T0, pEccWeierBasicDomainParams->pA, byteLenP, operandSize);
    MCUXCLPKC_FP_CALC_MC1_MM(WEIER_A, ECC_T0, ECC_PQSQR, ECC_P);
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_WeierECC_GenerateDomainParams, WEIER_B, pEccWeierBasicDomainParams->pB, byteLenP, operandSize);

    /* Import the base point coordinates (x,y) to buffers (ECC_S0,ECC_S1). */
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_WeierECC_GenerateDomainParams, ECC_S0, pEccWeierBasicDomainParams->pG, byteLenP, operandSize);
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFEROFFSET_DI_BALANCED(mcuxClEcc_WeierECC_GenerateDomainParams, ECC_S1, pEccWeierBasicDomainParams->pG, byteLenP, byteLenP, operandSize);

    pOperands[WEIER_VX0] = pOperands[ECC_S0];
    pOperands[WEIER_VY0] = pOperands[ECC_S1];

    /* Perform basic domain parameter checks */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_Weier_DomainParamsCheck(pSession, byteLenP, byteLenN));

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("32-bit aligned UPTRT table is assigned in CPU workarea")
    uint32_t *pOperands32 = (uint32_t *)pOperands;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

    /* Calculate R3N, and then reduce R2N < N and R2P < P. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("2u * operandSize fits into uint16_t")
    MCUXCLMATH_FP_QDASH(ECC_T3, ECC_NS, ECC_N, ECC_T0, (uint16_t) (2u * operandSize));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_GenerateDomainParams_Reduce_R2N_R2P,
                        mcuxClEcc_FUP_GenerateDomainParams_Reduce_R2N_R2P_LEN);

    /**********************************************************/
    /* Optionally, generate the pre-computed point            */
    /**********************************************************/

    if (MCUXCLECC_OPTION_GENERATEPRECPOINT_YES == (options & MCUXCLECC_OPTION_GENERATEPRECPOINT_MASK))
    {
        /* Convert the affine base point coordinates (x,y) stored in ECC_S0 and ECC_S1 to
         * Jacobian coordinates (X:Y:Z=1) in MR and store them in buffers (WEIER_X0,WEIER_Y0,WEIER_Z).
         * Also initialize the relative Z-coordinate Z' as 1 in MR and store it in WEIER_ZA. */
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_GenerateDomainParams_Convert_G_toJacMR,
                            mcuxClEcc_FUP_GenerateDomainParams_Convert_G_toJacMR_LEN);

        /* Calculate prec point PrecG = 2^(byteLenN * 4) * G using function mcuxClEcc_RepeatPointDouble.
         * Input/output buffers of mcuxClEcc_RepeatPointDouble are set as follows:
         *
         * Input:
         *  - ECC_VX2, ECC_VY2, ECC_VZ is set to the Jacobian coordinates (X:Y:Z=1) of the base point in buffers (WEIER_X0,WEIER_Y0,WEIER_Z)
         *  - ECC_VZ2 is set to the relative Jacobian coordinate Z'=1 stored in WEIER_ZA
         * Output:
         *  - ECC_VX0, ECC_VY0, ECC_VZ0 are set to buffers (WEIER_XA,WEIER_YA,WEIER_ZA) to store the result precG in relative Jacobian coordinates
         * Temp:
         *  - ECC_VT is set to temp buffer ECC_S2
         *
         * NOTE: Since the input Z-coordinate is 1 in MR, the resulting relative Jacobian coordinate is in fact the Z-coordinate
         *       of the result. So, ECC_VX0, ECC_VY0, ECC_VZ0 will effectively contains Jacobian coordinates for precG. */
//      MCUXCLPKC_WAITFORREADY()  <== unnecessary, because VX0/VY0/VZ0/VZ/VX2/VY2/VZ2 are not used in the FUP program before.
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX0, WEIER_XA);
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VZ0, WEIER_ZA);
        MCUXCLECC_COPY_PKCOFFSETPAIR_ALIGNED(pOperands32, WEIER_VX2, WEIER_X0);
        pOperands[WEIER_VZ2] = pOperands[WEIER_ZA];
        pOperands[WEIER_VT] = pOperands[ECC_S2];

        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("byteLenN * 8U cannot overflow.")
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_RepeatPointDouble((byteLenN * 8u) / 2u));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

        /* Convert precG to affine coordinates in NR and store them in (WEIER_X0,WEIER_Y0). */
        MCUXCLMATH_FP_MODINV(ECC_T0, WEIER_ZA, ECC_P, ECC_T1);
        /* MISRA Ex. 22, while(0) is allowed */
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_Weier_ConvertJacToAffine,
                            mcuxClEcc_FUP_Weier_ConvertJacToAffine_LEN);
    }
    else if (MCUXCLECC_OPTION_GENERATEPRECPOINT_NO != (options & MCUXCLECC_OPTION_GENERATEPRECPOINT_MASK))
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Do nothing. */
    }


    /**********************************************************/
    /* Initialize optimized domain parameters struct at the   */
    /* start of target memory area                            */
    /**********************************************************/

    /* Interpret start of memory area pEccWeierDomainParams as struct of type mcuxClEcc_Weier_DomainParams_t */
    mcuxClEcc_Weier_DomainParams_t *pDomainParams = (mcuxClEcc_Weier_DomainParams_t *) pEccWeierDomainParams;

    /* Initialize pointers to where the domain parameters shall be stored */
    uint8_t *pDomainParamBuffers = (uint8_t *) pEccWeierDomainParams + sizeof(mcuxClEcc_Weier_DomainParams_t);
    pDomainParams->common.pFullModulusP = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_PFULL;
    pDomainParams->common.pFullModulusN = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_NFULL(byteLenP);
    pDomainParams->common.pR2P = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_R2P(byteLenP, byteLenN);
    pDomainParams->common.pR2N = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_R2N(byteLenP, byteLenN);
    pDomainParams->common.pCurveParam1 = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_CP1(byteLenP, byteLenN);
    pDomainParams->common.pCurveParam2 = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_CP2(byteLenP, byteLenN);
    pDomainParams->common.pGx = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_GX(byteLenP, byteLenN);
    pDomainParams->common.pGy = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_GY(byteLenP, byteLenN);
    pDomainParams->common.pPrecPoints = pDomainParamBuffers + MCUXCLECC_CUSTOMPARAMS_OFFSET_PP(byteLenP, byteLenN);


    /**********************************************************/
    /* Fill optimized domain parameters                       */
    /**********************************************************/

    /* Initialize lengths and function pointers in optimized domain parameter struct */
    pDomainParams->common.byteLenP = (uint16_t) byteLenP;
    pDomainParams->common.byteLenN = (uint16_t) byteLenN;
    pDomainParams->common.pScalarMultFunctions = &mcuxClEcc_Weier_ScalarMultFunctions;

    /* Export full moduli for p and n to optimized domain parameter struct. */
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pFullModulusP, ECC_PFULL, byteLenP + MCUXCLPKC_WORDSIZE);
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pFullModulusN, ECC_NFULL, byteLenN + MCUXCLPKC_WORDSIZE);

    /* Export Montgomery parameters R2P and R2N to optimized domain parameter struct. */
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pR2P, ECC_PQSQR, byteLenP);
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pR2N, ECC_NQSQR, byteLenN);

    /* Copy domain parameters a and b to optimized domain parameter struct.
     *
     * NOTE: This is done in two steps via imports to/exports from the PKC RAM
     *       because no ordinary memory copy with endianess reversal exists. */
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_WeierECC_GenerateDomainParams, ECC_T0, pEccWeierBasicDomainParams->pA, byteLenP, operandSize);
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pCurveParam1, ECC_T0, byteLenP);
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pCurveParam2, WEIER_B, byteLenP);

    /* Export base point coordinates to optimized domain parameter struct. */
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pGx, ECC_S0, byteLenP);
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pGy, ECC_S1, byteLenP);

    if (MCUXCLECC_OPTION_GENERATEPRECPOINT_YES == (options & MCUXCLECC_OPTION_GENERATEPRECPOINT_MASK))
    {
        /* Optionally, export prec point coordinates to optimized domain parameter struct. */
        MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pPrecPoints, WEIER_X0, byteLenP);
        MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pDomainParams->common.pPrecPoints + byteLenP, WEIER_Y0, byteLenP);
    }
    else if (MCUXCLECC_OPTION_GENERATEPRECPOINT_NO != (options & MCUXCLECC_OPTION_GENERATEPRECPOINT_MASK))
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Do nothing. */
    }

    /* Import order n from input buffer and output buffer, compare to check if there are equal */
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_WeierECC_GenerateDomainParams, ECC_T0, pEccWeierBasicDomainParams->pN, byteLenN, operandSize);
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(ECC_T1, pDomainParams->common.pFullModulusN + MCUXCLPKC_WORDSIZE, byteLenN, operandSize);

    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_T0, ECC_T1);
    uint32_t zeroFlag_checkN = MCUXCLPKC_WAITFORFINISH_GETZERO();

    if (MCUXCLPKC_FLAG_ZERO == zeroFlag_checkN)
    {
        /**********************************************************/
        /* Clean up                                               */
        /**********************************************************/
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);

        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUXCLSESSION_EXIT(pSession, mcuxClEcc_WeierECC_GenerateDomainParams, diRefValue, MCUXCLECC_STATUS_OK, MCUXCLECC_STATUS_FAULT_ATTACK,
            MCUXCLECC_FP_WEIERECC_GENERATEDOMAINPARAMS_FINAL(options));
    }
    MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
}
