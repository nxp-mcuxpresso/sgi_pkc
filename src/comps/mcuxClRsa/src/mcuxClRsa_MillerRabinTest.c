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

/** @file  mcuxClRsa_MillerRabinTest.c
 *  @brief mcuxClRsa: function, which is called to perform  the Miller-Rabin
 *  probabilistic primality tests.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_Macros.h>

#include <mcuxClRandom_Constants.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal_Functions.h>

#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <mcuxClRandom_Functions.h>
#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_MillerRabinTest_FUP.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>
#include <internal/mcuxClRandom_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_MillerRabinTest)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_MillerRabinTest(
  mcuxClSession_Handle_t pSession,
  uint32_t              iP_iT,
  uint32_t              keyBitLength,
  const uint32_t        numberTestIterations
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_MillerRabinTest);


  /****************************************************************************/
  /* Initialization - Prepare buffers in PKC workarea, setup UPTR table       */
  /****************************************************************************/

  /* Set init status to FAILED */
  mcuxClRsa_Status_t status = MCUXCLRSA_STATUS_INTERNAL_TESTPRIME_MRT_FAILED;

  /* Backup Uptrt to recover in the end */
  const uint16_t *backupPtrUptrt = MCUXCLPKC_GETUPTRT();

  /* Create and set local Uptrt table. */
  uint32_t pOperands32[(MCUXCLRSA_INTERNAL_MILLERRABIN_UPTRT_SIZE + 1u) / 2u];

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("16-bit UPTRT table is assigned in CPU workarea")
  uint16_t *pOperands = (uint16_t *) pOperands32;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

  /* Get iP and iT indices */
  uint32_t uptrtIndexTmp = (iP_iT) & 0xFFu;
  uint32_t uptrtIndexPrimeCandidate = (iP_iT >> 8) & 0xFFu;

  /* PKC buffer sizes */
  const uint32_t byteLenPrime = (keyBitLength / 2u) / 8u; /* keyBitLength is multiple of 8 */
  const uint32_t pkcOperandSize = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(byteLenPrime);
  const uint32_t pkcBlindSize = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(MCUXCLRSA_INTERNAL_MOD_BLINDING_SIZE);
  const uint32_t pkcBlindOperandSize = pkcOperandSize + pkcBlindSize;
  const uint32_t bufferSizeQSquared = pkcBlindOperandSize;                        // size of temp buffer QSquared
  const uint32_t bufferSizeResult = pkcBlindOperandSize + MCUXCLRSA_PKC_WORDSIZE;  // size of the result of the exponentiation
  const uint32_t bufferSizeX = pkcBlindOperandSize + MCUXCLRSA_PKC_WORDSIZE;       // size of the base number of the exponentiation
  const uint32_t bufferSizeT0 = pkcBlindOperandSize + MCUXCLRSA_PKC_WORDSIZE;      // size of temp buffer T0
  const uint32_t bufferSizeT1 = pkcBlindOperandSize + MCUXCLRSA_PKC_WORDSIZE;      // size of temp buffer T1
  const uint32_t bufferSizeT2 = pkcBlindOperandSize + MCUXCLRSA_PKC_WORDSIZE;      // size of temp buffer T2
  const uint32_t bufferSizeT3 = pkcBlindOperandSize + MCUXCLRSA_PKC_WORDSIZE;      // size of temp buffer T3
  const uint32_t bufferSizeTE = 6u * MCUXCLRSA_PKC_WORDSIZE;                       // size of temp buffer TE

  /* Prepare buffers in PKC workarea */
  uint8_t *pNb = MCUXCLPKC_OFFSET2PTR(backupPtrUptrt[uptrtIndexTmp]) + MCUXCLRSA_PKC_WORDSIZE /* Offset for nDash */;
  uint8_t *pQSquared = pNb + pkcBlindOperandSize;
  uint8_t *pResult = pQSquared + bufferSizeQSquared;
  uint8_t *pX = pResult + bufferSizeResult;
  uint8_t *pT0 = pX + bufferSizeX;
  uint8_t *pT1 = pT0 + bufferSizeT0;
  uint8_t *pT2 = pT1 + bufferSizeT1;
  uint8_t *pT3 = pT2 + bufferSizeT2;
  uint8_t *pTE = pT3 + bufferSizeT3;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("PKC buffers are CPU-word aligned")
  uint32_t *pR32 = (uint32_t *)pTE; /* uses the same space as TE */
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  /* Allocate space for the temporary buffers for exponent (aligned to CPU word, length shall be a multiple of CPU word and greater than @p byteLenExp) */
  uint8_t *pExp = pTE + bufferSizeTE;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("PKC buffers are CPU-word aligned")
  uint32_t * pExpTemp = (uint32_t *) pExp + (pkcOperandSize / sizeof(uint32_t));  /* size MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(byteLenPrime + 1u) */
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  /* Setup UPTR table */
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_PRIMECANDIDATE] = backupPtrUptrt[uptrtIndexPrimeCandidate];
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_NB] = MCUXCLPKC_PTR2OFFSET(pNb);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_QSQUARED] = MCUXCLPKC_PTR2OFFSET(pQSquared);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT] = MCUXCLPKC_PTR2OFFSET(pResult);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_X] = MCUXCLPKC_PTR2OFFSET(pX);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T0] = MCUXCLPKC_PTR2OFFSET(pT0);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T1] = MCUXCLPKC_PTR2OFFSET(pT1);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T2] = MCUXCLPKC_PTR2OFFSET(pT2);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T3] = MCUXCLPKC_PTR2OFFSET(pT3);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_TE] = MCUXCLPKC_PTR2OFFSET(pTE);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_EXP] = MCUXCLPKC_PTR2OFFSET(pExp);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_R32] = MCUXCLPKC_PTR2OFFSET((uint8_t *)pR32);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_CONSTANT] = 1u;

  /* Set UPTRT table */
  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_SETUPTRT(pOperands);

  /* Set length of operands */
  MCUXCLPKC_PS1_SETLENGTH(pkcBlindOperandSize, pkcBlindOperandSize);
  MCUXCLPKC_PS2_SETLENGTH_REG(pkcOperandSize);  /* MCLEN on higher 16 bits is not used. */


  /*****************************************************************/
  /* Compute m (exp) = (PrimeCandidate-1) / 2^a                    */
  /* NOTE: a=1 since the PrimeCandidate is congruent 3 mod 4       */
  /* m is kept in FXRAM memory after TE                            */
  /*****************************************************************/

  MCUXCLPKC_FP_CALC_OP2_SHR(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_EXP, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_PRIMECANDIDATE, 1);

  /*****************************************************************/
  /* Compute blinded modulus w_b=w*r32 (w:=PrimeCandidate).        */
  /*****************************************************************/

  /* Generate r32 - odd random number used for blinding */
  pR32[0] = mcuxClRandom_ncGenerateWord_Internal(pSession);

  /* Make it odd */
  pR32[0] |= 0x1u;

  /* Clear part not overwritten when generating r32. */
#if !((MCUXCLPKC_WORDSIZE == 8u) && (MCUXCLRSA_INTERNAL_MOD_BLINDING_SIZE == 4u))
  #error "This implementation (clearing of B buffer) only supports 64-bit PKC word and 32-bit blinding value."
#endif
  pR32[1] = 0u;

  /* Compute blinded modulus w_b=w*r32 */
  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS2_SETLENGTH(pkcOperandSize, pkcBlindSize);
  MCUXCLPKC_FP_CALC_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_PRIMECANDIDATE, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_R32);

  /*****************************************************************/
  /* Prepare Montgomery parameters for modular operations          */
  /*****************************************************************/

  /* Calculate Ndash of w (it is needed to convert result for exponentiation from Montgomery to normal representation). */
  MCUXCLMATH_FP_NDASH(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_PRIMECANDIDATE, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T0);

  /* Calculate Ndash of w_b. */
  MCUXCLMATH_FP_NDASH(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T0);

  /* Calculate QSquared */
  MCUXCLMATH_FP_SHIFTMODULUS(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T1, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_NB); //shift modulus
  MCUXCLMATH_FP_QSQUARED(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_QSQUARED /* QSquared */, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T1,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T0);

  /* Clear buffer for the witness */
  MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT, 0u);

  /***************************************************************************/
  /* Set iteration counter, length of operands and start Miller Rabin test   */
  /***************************************************************************/
  uint32_t counter = 0;

  MCUX_CSSL_FP_COUNTER_STMT(uint32_t witnessLoopCounterMain = 0 /* flow protection: count execution of loops */);

  /* Get pointer to the witness */
  uint8_t * pWitness = MCUXCLPKC_OFFSET2PTR(pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT]);

  /* Set length of operands */
  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS2_SETLENGTH_REG(pkcOperandSize);  /* MCLEN on higher 16 bits is not used. */

  MCUXCLBUFFER_INIT(pBufWitness, NULL, pWitness, byteLenPrime);

  MCUX_CSSL_FP_LOOP_DECL(mainLoopFp);

  uint32_t executedIterations = 0u;

  do
  {
    uint32_t carryFlag_check = MCUXCLPKC_FLAG_CARRY;
    do{

      /***************************************************************************/
      /* Get random integer b of length equal to prime candidate from an RBG.    */
      /***************************************************************************/

      MCUX_CSSL_FP_COUNTER_STMT(++witnessLoopCounterMain);
      MCUX_CSSL_FP_FUNCTION_CALL(randomGenerateResult, mcuxClRandom_generate(pSession,
                                                               pBufWitness,
                                                               byteLenPrime));
      MCUXCLSESSION_CHECK_ERROR_FAULT(pSession, randomGenerateResult);

      /* If ((b <= 1) or (b >= PrimeCandidate - 1)), then generate new b, otherwise b is accepted. */

      /* Compute PrimeCandidate-2 */
      MCUXCLPKC_FP_CALC_OP2_SUB_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T0, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_PRIMECANDIDATE, 2);
      /* Compare PrimeCandidate-2 and b */
      MCUXCLPKC_FP_CALC_OP2_CMP(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T0, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT);
      carryFlag_check = MCUXCLPKC_WAITFORFINISH_GETCARRY();
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_CONDITIONAL((MCUXCLPKC_FLAG_NOCARRY == carryFlag_check), MCUXCLPKC_FP_CALLED_CALC_OP2_SUB_CONST));
      if(MCUXCLPKC_FLAG_NOCARRY == carryFlag_check)
      {
        /* Compare 2 and b */
        MCUXCLPKC_FP_CALC_OP2_SUB_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_X, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT, 2);
        carryFlag_check = MCUXCLPKC_WAITFORFINISH_GETCARRY();
      }
    }while(MCUXCLPKC_FLAG_NOCARRY != carryFlag_check);

    /***************************************************************************/
    /* Compute z_m = b_m^m mod w_b (using secure exponentiation)               */
    /***************************************************************************/

    /* Convert b to Montgomery representation i.e. b_m = b*QSquared mod w_b */
    MCUXCLPKC_FP_CALC_MC1_MM(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_X /* b_m */, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT /* b */,
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_QSQUARED /* QSquared */, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_NB);
    MCUXCLPKC_WAITFORFINISH();

    /* SREQI_RSA_0: DI protect the byte length of the exponent. Will be balanced in the call to mcuxClMath_SecModExp(). */
    MCUX_CSSL_DI_RECORD(MillerRabinTest_SecModExp, byteLenPrime);

    /* Copy m to the RESULT buffer. SecModExp overwrites the exponent provided in RESULT buffer, but m should be kept. */
    MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT, 0u);
    MCUXCLPKC_FP_CALC_OP2_OR_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_EXP, 0u);

    /*
     * Perform secure exponentiation z_m = b_m^m mod w_b.
     * Result z_m is in Montgomery representation.
     * PS1 LEN and MCLEN was already initialized OPLEN = MCLEN = pkcPrimeByteLength + pkcBlindSize,
     */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(MCUXCLMATH_SECMODEXP(
      pSession,
      pExpTemp,
      byteLenPrime,
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT, /* Result (z_bm), and exponent m */
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_X,      /* Montgomery representation of base number */
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_NB, /* Modulus, NDash of the modulus should be stored in front of it */
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_TE,
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T0,
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T1,
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T2,
      MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_T3
    ));

    /*
     * Call the FUP to do the below steps:
     * Convert from Montgomery to normal representation (modular reduction also removes the blinding from result).
     * Normalize the result (case if R > N).
     * Check if z == 1: if true then the test passed, otherwise another check is performed.
     */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS2_SETLENGTH(pkcBlindOperandSize, pkcOperandSize); // The MCLEN is only relevant to mcuxClRsa_MillerRabinTest_ReducAndCheck_FUP operations
    MCUXCLPKC_FP_CALCFUP(mcuxClRsa_MillerRabinTest_ReducAndCheck_FUP,
        mcuxClRsa_MillerRabinTest_ReducAndCheck_FUP_LEN);

    MCUX_CSSL_FP_LOOP_ITERATION(mainLoopFp, MCUXCLPKC_FP_CALLED_CALC_MC1_MM,
                               MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
                               MCUXCLPKC_FP_CALLED_CALC_OP2_OR_CONST,
                               MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_SecModExp),
                               MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));

    uint32_t zeroFlag_check = MCUXCLPKC_WAITFORFINISH_GETZERO();

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_CONDITIONAL((MCUXCLPKC_FLAG_ZERO != zeroFlag_check), MCUXCLPKC_FP_CALLED_CALC_OP2_SUB_CONST, MCUXCLPKC_FP_CALLED_CALC_OP2_CMP));

    /* Check if z == 1: if true then the test passed, otherwise another check is performed */
    if(MCUXCLPKC_FLAG_ZERO != zeroFlag_check)
    {
      /*******************************************************************************************************************/
      /* Check the second condition.                                                                                     */
      /* if ((z == PrimeCandidate-1), test passed, then continue. Otherwise, it means  that PrimeCandidate is composite, */
      /* and function returns MCUXCLRSA_STATUS_INTERNAL_TESTPRIME_MRT_FAILED error code                                   */
      /*******************************************************************************************************************/

      /* Compute PrimeCandidate-1 */
      MCUXCLPKC_FP_CALC_OP2_SUB_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT /* PrimeCandidate-1 */, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_PRIMECANDIDATE, 1);
      /* Compare PrimeCandidate-1 and z */
      MCUXCLPKC_FP_CALC_OP2_CMP(MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_RESULT /* PrimeCandidate-1 */, MCUXCLRSA_INTERNAL_UPTRTINDEX_MILLERRABIN_X /* z */);
      zeroFlag_check = MCUXCLPKC_WAITFORFINISH_GETZERO();
      if(MCUXCLPKC_FLAG_ZERO != zeroFlag_check)
      {
        /* Did not pass test, it is not prime, stop MillerRabin test. */
        break;
      }
    }

    /* Increment the M-R test counter */
    ++counter;
    zeroFlag_check = MCUXCLPKC_GETZERO();
    executedIterations += zeroFlag_check;

  /******************************************************************************************************/
  /* If counter == numberTestIterations, the prime candidate pass the M-R test, it is probably prime,   */
  /* function returns MCUXCLRSA_STATUS_KEYGENERATION_OK.                                                 */
  /* Otherwise, continue the test in loop              .                                                */
  /******************************************************************************************************/
  }while(counter < numberTestIterations);

  if (counter == numberTestIterations)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_getMillerRabinTestIterations));
    MCUX_CSSL_FP_FUNCTION_CALL(needNumberTestIterations, mcuxClRsa_getMillerRabinTestIterations(keyBitLength / 2u));
    if (needNumberTestIterations != executedIterations)
    {
      MCUXCLSESSION_FAULT(pSession, MCUXCLRSA_STATUS_FAULT_ATTACK);
    }
    /* This means all rounds have passed test */
    status = MCUXCLRSA_STATUS_KEYGENERATION_OK;
  }

  /* Recover Uptrt */
  MCUXCLPKC_SETUPTRT(backupPtrUptrt);

  MCUX_CSSL_FP_COUNTER_STMT(uint32_t mainLoopCounter = (counter == numberTestIterations) ? numberTestIterations : (counter + 1u));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_MillerRabinTest,
                            status,
                            MCUXCLPKC_FP_CALLED_CALC_OP2_SHR,
                            MCUXCLPKC_FP_CALLED_CALC_MC2_PM_PATCH,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_NDash),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_NDash),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_QSquared),
                            MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) * witnessLoopCounterMain,
                            MCUXCLPKC_FP_CALLED_CALC_OP2_SUB_CONST * witnessLoopCounterMain,
                            MCUXCLPKC_FP_CALLED_CALC_OP2_CMP * witnessLoopCounterMain,
                            MCUX_CSSL_FP_LOOP_ITERATIONS(mainLoopFp, mainLoopCounter));

}
