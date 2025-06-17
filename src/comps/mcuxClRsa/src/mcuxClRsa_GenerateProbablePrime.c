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

/** @file  mcuxClRsa_GenerateProbablePrime.c
 *  @brief mcuxClRsa: function, which is called to generates probably prime number
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslDataIntegrity.h>

#include <mcuxClRsa.h>
#include <mcuxClKey.h>
#include <internal/mcuxClRandom_Internal_Functions.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_GenerateProbablePrime)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_GenerateProbablePrime(
  mcuxClSession_Handle_t           pSession,
  mcuxClRsa_KeyEntry_t *           pE,
  mcuxClRsa_KeyEntry_t *           pPrimeCandidate,
  const uint32_t                  keyBitLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_GenerateProbablePrime,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CONST);

    MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, (uint32_t)pSession);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(keyBitLength, 8u * MCUXCLRSA_MIN_MODLEN, 8u * MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)

    mcuxClRsa_Status_t status = MCUXCLKEY_STATUS_FAILURE;
    uint32_t loopCounter = 0u;
    const uint32_t loopMax = 5u * (keyBitLength / 2u);
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t cntRandomGen = 0u);
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t cntTestPrime = 0u);

    /* Little-endian representation of 0xb504f333f9de6485u, which is 64 most significant bits of sqrt(2)(2^(nlen/2)-1) rounded up */
    static const uint8_t numToCompare[] = {0x85u, 0x64u, 0xDEu, 0xF9u, 0x33u, 0xF3u, 0x04u, 0xB5u};
    /* Little-endian representation of 0xC0CFD797u, which is the product of the first 9 prime numbers starting from 3*/
    static const uint8_t a0[] = {0x97u, 0xD7u, 0xCFu, 0xC0u};

    /*
    * Initialization:
    * - allocate buffers in PKC RAM
    * - copy 0xb504f333f9de6485u value into buffer located in PKC RAM
    * - copy A0 value into buffer located in PKC RAM
    * - update session (PKC workarea used...)
    */

    const uint32_t pkcWaSizeWord = (3u * MCUXCLRSA_PKC_WORDSIZE) / (sizeof(uint32_t));
    uint8_t *pPkcWorkarea = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, pkcWaSizeWord);
    uint8_t *pNumToCompare = pPkcWorkarea;
    uint8_t *pA0 = pPkcWorkarea + MCUXCLRSA_PKC_WORDSIZE;
    uint8_t *pConst3 = pA0 + MCUXCLRSA_PKC_WORDSIZE;

    /* Setup UPTR table */
    const uint32_t cpuWaSizeWord =  MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE_WO_TESTPRIME_AND_MILLERRABIN(keyBitLength/8u/2u) / (sizeof(uint32_t));
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("16-bit UPTRT table is assigned in CPU workarea")
    uint16_t * pOperands = (uint16_t *) mcuxClSession_allocateWords_cpuWa(pSession, cpuWaSizeWord);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_NUMTOCOMPARE] = MCUXCLPKC_PTR2OFFSET(pNumToCompare);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_A0] = MCUXCLPKC_PTR2OFFSET(pA0);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_CANDIDATE_LSWORD] = MCUXCLPKC_PTR2OFFSET(pPrimeCandidate->pKeyEntryData);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_WORD_CONST3] = MCUXCLPKC_PTR2OFFSET(pConst3);

    const uint32_t iNumToCmp_iA0 = ((uint32_t)MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_NUMTOCOMPARE << 8u) | MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_A0;

    /* Backup Ps1 length and UPTRT, restore them when returning */
    uint16_t *bakUPTRT = MCUXCLPKC_GETUPTRT();
    uint32_t bakPs1LenReg = MCUXCLPKC_PS1_GETLENGTH_REG();
    uint32_t bakPs2LenReg = MCUXCLPKC_PS2_GETLENGTH_REG();

    /* Set UPTRT table */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_SETUPTRT(pOperands);

    MCUXCLPKC_PS1_SETLENGTH(0u, MCUXCLRSA_PKC_WORDSIZE);
    MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_NUMTOCOMPARE, 0u);
    MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_A0, 0u);
    MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_WORD_CONST3, 0u);
    MCUXCLPKC_WAITFORFINISH();

    pConst3[0] = 3u;

    /* Balance DI for call to mcuxClMemory_copy_int */
    MCUX_CSSL_DI_RECORD(memCopyNumToCompare, (pNumToCompare + MCUXCLRSA_PKC_WORDSIZE));
    MCUX_CSSL_DI_RECORD(memCopyNumToCompare, numToCompare);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
      pNumToCompare + MCUXCLRSA_PKC_WORDSIZE - sizeof(numToCompare),
      numToCompare,
      sizeof(numToCompare)
    ));

    /* Balance DI for call to mcuxClMemory_copy_int */
    MCUX_CSSL_DI_RECORD(memCopyA0, pA0);
    MCUX_CSSL_DI_RECORD(memCopyA0, a0);
    MCUX_CSSL_DI_RECORD(memCopyA0, sizeof(a0));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(pA0, a0, sizeof(a0)));

    MCUXCLBUFFER_INIT(pBufKeyEntryData, NULL, pPrimeCandidate->pKeyEntryData, pPrimeCandidate->keyEntryLength);
    MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, (uint32_t)pBufKeyEntryData);

    /* Protect the input length and pointer to the prime candidate, by expunging them from DI.
     * Note that pPrimeCandidate->keyEntryLength is not explicitly expunged, as this is already
     * done by the first call to mcuxClRandom_generate_internal, for which pPrimeCandidate->keyEntryLength
     * is not RECORDded in this function. */
    MCUX_CSSL_DI_EXPUNGE(primeCandidate, pPrimeCandidate->pKeyEntryData);

    /* Get number of Miller-Rabin test iterations */
    /* Returns the number of Miller-Rabin test iterations for given prime bit length */
    MCUX_CSSL_FP_FUNCTION_CALL(numberMillerRabinTestIterations, mcuxClRsa_getMillerRabinTestIterations(keyBitLength / 2u));

    do
    {
        /*
        * Generate a random prime candidate for given key size using DRBG:
        *    - Ensure that prime candidate is odd;
        *    - Ensure that prime candidate is congruent 3 mod 4 (this deviation from FIPS 186-4 has been approved).
        *
        *    The session pointed to by pSession shall be initialized with the entropy level (security strength)
        *    in accordance with the value of keyBitLength, as specified in SP 800-57, Part 1.
        *
        * Used functions: RNG provided through the pSession
        */
        MCUX_CSSL_FP_COUNTER_STMT(cntRandomGen++);

        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_generate_internal(pSession, pBufKeyEntryData, pPrimeCandidate->keyEntryLength, NULL));

        MCUX_CSSL_FP_COUNTER_STMT(cntTestPrime++);
        MCUXCLPKC_FP_CALC_OP1_OR(MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_CANDIDATE_LSWORD,
                                MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_CANDIDATE_LSWORD,
                                MCUXCLRSA_INTERNAL_UPTRTINDEX_GENPRIME_WORD_CONST3);

        /*mcuxClRsa_TestPrimeCandidate can return MCUXCLRSA_STATUS_KEYGENERATION_OK or other return values where the prime test failed */
        MCUX_CSSL_FP_FUNCTION_CALL(retTest, mcuxClRsa_TestPrimeCandidate(pSession, pE, pPrimeCandidate, keyBitLength, iNumToCmp_iA0, numberMillerRabinTestIterations));
        MCUX_CSSL_ANALYSIS_COVERITY_START_FALSE_POSITIVE(MISRA_C_2012_Rule_15_7, "There is a non-empty terminating else statement")

        if (MCUXCLRSA_STATUS_KEYGENERATION_OK == retTest)
        {
            status = retTest;
            loopCounter++;
            break;
        }
        else if (MCUXCLRSA_STATUS_INTERNAL_TESTPRIME_CMP_FAILED != retTest)
        {
            loopCounter++;
        }
        else
        {
            /* Record parameters for the call to mcuxClRandom_generate_internal */
            MCUX_CSSL_DI_RECORD(randomGenerateParams, pSession);
            MCUX_CSSL_DI_RECORD(randomGenerateParams, pBufKeyEntryData);
            MCUX_CSSL_DI_RECORD(randomGenerateParams, pPrimeCandidate->keyEntryLength);
        }
        MCUX_CSSL_ANALYSIS_COVERITY_STOP_FALSE_POSITIVE(MISRA_C_2012_Rule_15_7)
    } while(loopCounter < loopMax);

    /* Balance DI for the calls to mcuxClRandom_generate_internal */
    MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, (uint32_t)pSession * (loopCounter - 1u));
    MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, (uint32_t)pBufKeyEntryData * (loopCounter - 1u));
    MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, (uint32_t)pPrimeCandidate->keyEntryLength * (loopCounter - 1u));

    /* Recover session, Ps1 length and Uptrt */
    mcuxClSession_freeWords_pkcWa(pSession, pkcWaSizeWord);
    mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
    MCUXCLPKC_PS1_SETLENGTH_REG(bakPs1LenReg);
    MCUXCLPKC_PS2_SETLENGTH_REG(bakPs2LenReg);
    MCUXCLPKC_SETUPTRT(bakUPTRT);

    /* If generate probable prime is not successful, return MCUXCLKEY_STATUS_ITERATIONS_EXCEEDED to caller, through session */
    if (MCUXCLRSA_STATUS_KEYGENERATION_OK != status)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_ITERATIONS_EXCEEDED);
    }

    /* Check define outside of macro so the MISRA rule 20.6 does not get violated */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_GenerateProbablePrime,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_getMillerRabinTestIterations),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate_internal) * cntRandomGen,
        MCUXCLPKC_FP_CALLED_CALC_OP1_OR * cntTestPrime,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_TestPrimeCandidate) * cntTestPrime);

}

