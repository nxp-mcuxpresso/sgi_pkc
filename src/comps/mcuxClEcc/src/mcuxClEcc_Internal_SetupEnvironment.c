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
 * @file  mcuxClEcc_Internal_SetupEnvironment.c
 * @brief mcuxClEcc: implementation of mcuxClEcc_SetupEnvironment
 */


#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClMemory.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_FUP.h>

/**
 * This function sets up the general environment used by ECC functions.
 * In particular, it sets up the utilized co-processors, prepares the PKC workarea layout,
 * and initializes it for Montgomery arithmetic modulo p and n.
 *
 * Input:
 *  - pSession              Handle for the current CL session
 *  - pCommonDomainParams   Pointer to domain parameter struct passed via API
 *  - noOfBuffers           Number of PKC buffers to be allocated
 *
 * Result:
 *  - The pointer table has been properly setup in CPU workarea and PKC buffers have been allocated
 *  - The PKC state has been backed up in CPU workarea and the PKC has been enabled
 *  - ps1Len = (operandSize, operandSize)
 *  - Buffers ECC_PFULL and ECC_NFULL contain p'||p and n'||n, respectively
 *  - Buffers ECC_PS and ECC_NS contain the p resp. n shifted to the PKC word boundary
 *  - Buffers ECC_PQSQR and ECC_NQSQR contain the R^2 values modulo p and n, respectively
 *  - Virtual pointers ECC_P and ECC_N point to the second PKC word of ECC_PFULL and ECC_NFULL, respectively
 *  - Virtual pointers ECC_ZERO and ECC_ONE have been initialized with 0 and 1, respecitvely
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_SetupEnvironment)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_SetupEnvironment(mcuxClSession_Handle_t pSession,
                                                                        mcuxClEcc_CommonDomainParams_t *pCommonDomainParams,
                                                                        uint8_t noOfBuffers)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_SetupEnvironment);

    const uint32_t byteLenP = (uint32_t) pCommonDomainParams->byteLenP;
    const uint32_t byteLenN = (uint32_t) pCommonDomainParams->byteLenN;
    const uint32_t byteLenMax = ((byteLenP > byteLenN) ? byteLenP : byteLenN);
    const uint32_t operandSize = MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(byteLenMax);
    const uint32_t bufferSize = operandSize + MCUXCLPKC_WORDSIZE;

    /* Setup CPU workarea and PKC buffer. */
    const uint32_t byteLenOperandsTable = (sizeof(uint16_t)) * (ECC_NO_OF_VIRTUALS + (uint32_t) noOfBuffers);
    const uint32_t alignedByteLenCpuWa = MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_CpuWa_t)) + sizeof(uint32_t) /* Reserve 1 word for making UPTR table start from 64-bit aligned address */
                                          + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(byteLenOperandsTable);
    const uint32_t wordNumCpuWa = alignedByteLenCpuWa / (sizeof(uint32_t));
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 to Rule 11.3 - mcuxClEcc_CpuWa_t is 32 bit aligned")
    MCUX_CSSL_FP_FUNCTION_CALL(mcuxClEcc_CpuWa_t*, pCpuWorkarea, mcuxClSession_allocateWords_cpuWa(pSession, wordNumCpuWa));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()
    const uint32_t wordNumPkcWa = (bufferSize * (uint32_t) noOfBuffers) / (sizeof(uint32_t));  /* PKC bufferSize is a multiple of CPU word size. */
    MCUX_CSSL_FP_FUNCTION_CALL(const uint8_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(pSession, wordNumPkcWa));

    pCpuWorkarea->wordNumCpuWa = wordNumCpuWa;
    pCpuWorkarea->wordNumPkcWa = wordNumPkcWa;

    MCUXCLPKC_FP_REQUEST_INITIALIZE(pSession, mcuxClEcc_SetupEnvironment);

    /* Set PS1 MCLEN and LEN. */
    MCUXCLPKC_PS1_SETLENGTH(operandSize, operandSize);

    /* Setup UPTR table. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("MISRA Ex. 9 - Rule 11.3 - Cast to 16-bit pointer table")
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("Arithmetic to align pointers on 2 bytes")
    uint16_t *pOperands = (uint16_t *)MCUXCLCORE_ALIGN_TO_WORDSIZE(sizeof(uint64_t), (uint32_t)pCpuWorkarea + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_CpuWa_t))); /* Make UPTR table start from 64-bit aligned address */
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()
    /* MISRA Ex. 22, while(0) is allowed */
    MCUXCLPKC_FP_GENERATEUPTRT(& pOperands[ECC_NO_OF_VIRTUALS],
                              pPkcWorkarea,
                              (uint16_t) bufferSize,
                              noOfBuffers);
    MCUXCLPKC_SETUPTRT(pOperands);

    /* Setup virtual offsets to prime p and curve order n. */
    pOperands[ECC_P] = (pOperands[ECC_PFULL] + MCUXCLPKC_WORDSIZE) & 0xFFFFu;
    pOperands[ECC_N] = (pOperands[ECC_NFULL] + MCUXCLPKC_WORDSIZE) & 0xFFFFU;

    /* Initialize constants ONE = 0x0001 and ZERO = 0x0000 in uptr table. */
    pOperands[ECC_ONE]  = 0x0001u;
    pOperands[ECC_ZERO] = 0x0000u;

    /* Clear buffers P, N, PQSQR and NQSQR. */
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_SetupEnvironment_ClearBuffers,
                        mcuxClEcc_FUP_SetupEnvironment_ClearBuffers_LEN);
    MCUXCLPKC_WAITFORFINISH();

    /* Import prime p and order n, and corresponding Montgomery parameter (NDash). */

    MCUX_CSSL_DI_RECORD(sumOfMemCopyParams, (uint32_t)MCUXCLPKC_OFFSET2PTR(pOperands[ECC_PFULL]) + (uint32_t)pCommonDomainParams->pFullModulusP + MCUXCLPKC_WORDSIZE + byteLenP
                                    + (uint32_t)MCUXCLPKC_OFFSET2PTR(pOperands[ECC_NFULL]) + (uint32_t)pCommonDomainParams->pFullModulusN + MCUXCLPKC_WORDSIZE + byteLenN
                                    + (uint32_t)MCUXCLPKC_OFFSET2PTR(pOperands[ECC_PQSQR]) + (uint32_t)pCommonDomainParams->pR2P + byteLenP
                                    + (uint32_t)MCUXCLPKC_OFFSET2PTR(pOperands[ECC_NQSQR]) + (uint32_t)pCommonDomainParams->pR2N + byteLenN);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
      MCUXCLPKC_OFFSET2PTR(pOperands[ECC_PFULL]),
      (const uint8_t*)pCommonDomainParams->pFullModulusP,
      MCUXCLPKC_WORDSIZE + byteLenP
    ));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
      MCUXCLPKC_OFFSET2PTR(pOperands[ECC_NFULL]),
      (const uint8_t*)pCommonDomainParams->pFullModulusN,
      MCUXCLPKC_WORDSIZE + byteLenN
    ));

    /* Check p and n are odd (Math functions assume modulus is odd). */
    const volatile uint8_t * ptrP = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_P]);
    const volatile uint8_t * ptrN = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_N]);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("PKC buffer is CPU word aligned")
    uint32_t p0 = ((const volatile uint32_t *) ptrP)[0];
    uint32_t n0 = ((const volatile uint32_t *) ptrN)[0];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    if (0x01u != (0x01u & p0 & n0))
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    /* Import R^2 mod p and R^2 mod n. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
      MCUXCLPKC_OFFSET2PTR(pOperands[ECC_PQSQR]),
      (const uint8_t*)pCommonDomainParams->pR2P,
      byteLenP
    ));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
      MCUXCLPKC_OFFSET2PTR(pOperands[ECC_NQSQR]),
      (const uint8_t*)pCommonDomainParams->pR2N,
      byteLenN
    ));

    /* Calculate shifted modulus of p and n. */
    MCUXCLMATH_FP_SHIFTMODULUS(ECC_PS, ECC_P);
    MCUXCLMATH_FP_SHIFTMODULUS(ECC_NS, ECC_N);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_SetupEnvironment,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa),
        MCUXCLPKC_FP_CALLED_REQUEST_INITIALIZE,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_GenerateUPTRT),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus) );
}
