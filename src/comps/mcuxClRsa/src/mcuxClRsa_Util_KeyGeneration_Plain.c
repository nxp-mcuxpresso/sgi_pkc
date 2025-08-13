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

/** @file  mcuxClRsa_Util_KeyGeneration_Plain.c
 *  @brief mcuxClRsa: implementation of RSA key generation function
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslDataIntegrity.h>

#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Resource.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClPrng_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Util_KeyGeneration_Plain_FUP.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_Util_KeyGeneration_Plain)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_Util_KeyGeneration_Plain(
  mcuxClSession_Handle_t pSession,
  mcuxClKey_Generation_t generation,
  mcuxClKey_Handle_t privKey,
  mcuxClKey_Handle_t pubKey)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_Util_KeyGeneration_Plain);

  /* Protect key handles. This will be balanced when calling MCUXCLKEY_STORE_FP. */
  MCUX_CSSL_DI_RECORD(keyStore_private, privKey);
  MCUX_CSSL_DI_RECORD(keyStore_public, pubKey);

  /*
   * Initialization process to Check entropy provided by RNG and if E is FIPS compliant
   */
  const uint32_t bitLenKey = mcuxClKey_getSize(pubKey);
  const uint32_t byteLenKey = bitLenKey / 8u;

  const mcuxClRsa_KeyGeneration_ProtocolDescriptor_t * pProtocolDescriptor = (const mcuxClRsa_KeyGeneration_ProtocolDescriptor_t *) generation->pProtocolDescriptor;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to set the generic pointer.")
    mcuxClRsa_KeyEntry_t * pPublicExponent = (mcuxClRsa_KeyEntry_t *) &pProtocolDescriptor->pubExp;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()

  uint32_t byteLenE = 0u;

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(
    mcuxClRsa_Util_KeyGeneration_Init_PlainKey(
      pSession,
      pubKey,
      generation,
      &byteLenE,
      privKey));

  /* Initialize PKC. */
  MCUXCLPKC_FP_REQUEST_INITIALIZE(pSession, mcuxClRsa_Util_KeyGeneration_Plain);

  /*
   * Allocate buffers in PKC RAM
   * - size aligned to PKC word
   * - they are be stored in little-endian byte order
   * Memory layout: | nDash (FW) | P (pkcByteLenPrime) | nDash (FW) | Q (pkcByteLenPrime) | E (pkcByteLenKey) |
   */
  const uint32_t pkcByteLenKey = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(byteLenKey);
  const uint32_t byteLenPrime = byteLenKey / 2u;
  const uint32_t pkcByteLenPrime = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(byteLenPrime);

  /* Allocate space in session for p, q and e for now */
  uint32_t pkcWaSizeWord = (2u * (pkcByteLenPrime + MCUXCLRSA_PKC_WORDSIZE) + pkcByteLenKey) / (sizeof(uint32_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(pSession, pkcWaSizeWord));

  uint8_t *pPkcBufferP = pPkcWorkarea + MCUXCLRSA_PKC_WORDSIZE; /* offset for NDash */
  uint8_t *pPkcBufferQ = pPkcBufferP + pkcByteLenPrime + MCUXCLRSA_PKC_WORDSIZE; /* offset for NDash */
  uint8_t *pPkcBufferE = pPkcBufferQ + pkcByteLenPrime;

  /* Protect the lengths and pointers to the prime candidates, that will be balanced when calling mcuxClRsa_GenerateProbablePrime */
  MCUX_CSSL_DI_RECORD(generateProbablePrimeParams, pPkcBufferP);
  MCUX_CSSL_DI_RECORD(generateProbablePrimeParams, pPkcBufferQ);
  MCUX_CSSL_DI_RECORD(generateProbablePrimeParams, 2u * byteLenPrime);

  /* Setup UPTR table. */
  const uint32_t cpuWaSizeWord = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_UPTRT_SIZE * (sizeof(uint16_t)));
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("16-bit UPTRT table is assigned in CPU workarea")
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint16_t*, pOperands, mcuxClSession_allocateWords_cpuWa(pSession, cpuWaSizeWord));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

  MCUXCLPKC_SETUPTRT(pOperands);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_P] = MCUXCLPKC_PTR2OFFSET(pPkcBufferP);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_Q] = MCUXCLPKC_PTR2OFFSET(pPkcBufferQ);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_E] = MCUXCLPKC_PTR2OFFSET(pPkcBufferE);

  /*
   * Copy E to PKC RAM.
   * It is stored in little-endian byte order (copied with reverse order and without leading zeros).
   *
   *  Used functions: mcuxClPkc_ImportBigEndianToPkc
   */
  MCUXCLPKC_PS1_SETLENGTH(pkcByteLenPrime, pkcByteLenPrime);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer pPublicExponent has a compatible type and the access to keyEntryLength is valid")
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(byteLenE, 0u, pPublicExponent->keyEntryLength, MCUXCLRSA_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
  uint32_t leadingZerosE = pPublicExponent->keyEntryLength - byteLenE;
  MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_DI_BALANCED(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_E, pPublicExponent->pKeyEntryData + leadingZerosE, byteLenE, pkcByteLenPrime);

  /*
   * Generate prime p.
   * Continue if mcuxClRsa_GenerateProbablePrime returns MCUXCLRSA_STATUS_KEYGENERATION_OK.
   * In case of errors, the mcuxClRsa_GenerateProbablePrime function would do an early-exit via session.
   *
   * Used functions: mcuxClRsa_GenerateProbablePrime
   */
  mcuxClRsa_KeyEntry_t e;
  e.keyEntryLength = byteLenE;
  e.pKeyEntryData = pPkcBufferE;
  mcuxClRsa_KeyEntry_t p;
  p.keyEntryLength = byteLenPrime;
  p.pKeyEntryData = pPkcBufferP;

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_GenerateProbablePrime(pSession, &e, &p, bitLenKey));

  MCUX_CSSL_FP_COUNTER_STMT(uint32_t loopCounter = 0;)
  mcuxClRsa_KeyEntry_t d;
  d.keyEntryLength = 0; /* it will be computed by mcuxClRsa_ComputeD */
  const uint32_t pkcWaSizeWordD = (pkcByteLenKey + 2u * MCUXCLRSA_PKC_WORDSIZE) / sizeof(uint32_t);

  do
  {
    MCUX_CSSL_FP_COUNTER_STMT(++loopCounter;)

    /*
     * Generate prime q.
     * Continue if mcuxClRsa_GenerateProbablePrime returns MCUXCLRSA_STATUS_KEYGENERATION_OK.
     * In case of errors, the mcuxClRsa_GenerateProbablePrime function would do an early-exit via session.
     *
     * Used functions: mcuxClRsa_GenerateProbablePrime
     */
    mcuxClRsa_KeyEntry_t q;
    q.pKeyEntryData = pPkcBufferQ;
    q.keyEntryLength = byteLenPrime;
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_GenerateProbablePrime(pSession, &e, &q, bitLenKey));

    /*
     * Allocate PKC workarea for ComputeD if it has not been allocated. This workarea is also used for TestPQDistance as the temporary buffer.
     * Memory layout: | nDash (FW) | P (pkcByteLenPrime) | nDash (FW) | Q (pkcByteLenPrime) | E (pkcByteLenKey) | D (pkcByteLenKey + 2 FWs) |
     */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
    MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcBufferD, mcuxClSession_allocateWords_pkcWa(pSession, pkcWaSizeWordD));

    MCUXCLPKC_WAITFORREADY();
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_D] = MCUXCLPKC_PTR2OFFSET(pPkcBufferD);
    d.pKeyEntryData = pPkcBufferD;

    /* Protect pointers for mcuxClRsa_ComputeD */
    MCUX_CSSL_DI_RECORD(computeDParams, pPkcBufferP);
    MCUX_CSSL_DI_RECORD(computeDParams, pPkcBufferQ);
    MCUX_CSSL_DI_RECORD(computeDParams, pPkcBufferD);

    /*
     * Check if |p - q| <= 2^(nlen/2 - 100).
     * Continue if mcuxClRsa_TestPQDistance function returns MCUXCLRSA_STATUS_KEYGENERATION_OK
     * otherwise the function does an early-exit with MCUXCLKEY_STATUS_ERROR error code.
     *
     * Used functions: mcuxClRsa_TestPQDistance
     *
     * NOTE: This is a deviation from the method specified in the FIPS 186-4, where this check is performed while generating the prime q
     *       (see step 5.4 in Appendix B.3.3).
     *       The @ref mcuxClRsa_GenerateProbablePrime function does not perform this check, it is done after generating p and q.
     *       For this reason, if p and q does not meet this FIPS requirements, no new prime q number will be generated. Instead
     *       of function ends with error.
     *       Rationale of this deviation:
     *       This check will fail if at least 100 most significant bits of p and q are identical. This can happen
     *       with very low probability and it's usually treated as a hardware failure.
     */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClRsa_TestPQDistance(
        pSession,
        MCUXCLPKC_PACKARGS4(
          0,
          MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_P,
          MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_Q,
          MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_D /* used as a temporary buffer, it is > 3 * MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(16) */),
        pkcByteLenPrime));

    /*
     * Compute d := e^(-1) mod lcm(p-1, q-1)
     * If mcuxClRsa_ComputeD function returns MCUXCLRSA_STATUS_INTERNAL_PRIVEXP_INVALID, then go to step 7 (new q must be generated): new loop iteration.
     *
     * Used functions: mcuxClRsa_ComputeD
     */
    MCUX_CSSL_DI_RECORD(computeDParams, bitLenKey);

    MCUX_CSSL_FP_FUNCTION_CALL(retVal_ComputeD, mcuxClRsa_ComputeD(pSession, &e, &p, &q, &d, bitLenKey));

    /* The mcuxClRsa_ComputeD can return MCUXCLRSA_STATUS_KEYGENERATION_OK or MCUXCLRSA_STATUS_INTERNAL_PRIVEXP_INVALID */
    if(MCUXCLRSA_STATUS_KEYGENERATION_OK == retVal_ComputeD)
    {
      break;
    }
    else
    {
      /* pointer/length of Q will be expunged again when calling mcuxClRsa_GenerateProbablePrime */
      MCUX_CSSL_DI_RECORD(generateProbablePrimeParams, pPkcBufferQ);
      MCUX_CSSL_DI_RECORD(generateProbablePrimeParams, byteLenPrime);

      /* Free up the space used for priv exponent D */
      mcuxClSession_freeWords_pkcWa(pSession, pkcWaSizeWordD);
    }
  }
  while(true);

  /*
   * Compute n := p*q in a blinded way.
   *
   * Memory layout: | nDash (FW) | P (pkcByteLenPrime) | nDash (FW) | Q (pkcByteLenPrime) | E (pkcByteLenKey) | D (pkcByteLenKey) | N (pkcByteLenKey + FW) |
   *                  Rand (blindAlignLen) | P_b (blindedPrimeAlignLen) | Q_b (blindedPrimeAlignLen) | N_b (blindedModAlignLen) | RandSquare (blindSquaredAlignLen + FW) |
   */

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pkcByteLenKey, MCUXCLRSA_MIN_MODLEN, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pkcByteLenPrime, MCUXCLRSA_MIN_MODLEN / 2U, MCUXCLRSA_MAX_MODLEN / 2U, MCUXCLRSA_STATUS_INVALID_INPUT)
  const uint32_t blindLen = MCUXCLRSA_INTERNAL_MOD_BLINDING_SIZE;  // length in bytes of the random value used for blinding
  const uint32_t blindAlignLen = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(blindLen);
  const uint32_t blindSquaredAlignLen = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(blindLen * 2u);
  const uint32_t blindedPrimeAlignLen = pkcByteLenPrime + blindAlignLen;
  const uint32_t blindedModAlignLen = 2u * blindedPrimeAlignLen;

  const uint32_t pkcWaSizeWord2 = (pkcByteLenKey - MCUXCLRSA_PKC_WORDSIZE // N, the 2 FWs of D will be used for N
                                  + blindAlignLen // Rand
                                  + blindedPrimeAlignLen // P_b
                                  + blindedPrimeAlignLen // Q_b
                                  + blindedModAlignLen // N_b
                                  + blindSquaredAlignLen + MCUXCLRSA_PKC_WORDSIZE // RandSquare
                                  ) / sizeof(uint32_t);

  /* allocate the remaining space for computing N */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcWorkarea2, mcuxClSession_allocateWords_pkcWa(pSession, pkcWaSizeWord2));

  pkcWaSizeWord += (pkcWaSizeWordD + pkcWaSizeWord2);

  uint8_t *pPkcBufferN = pPkcWorkarea2 - 2u * MCUXCLRSA_PKC_WORDSIZE; // the 2 FWs of D will be used for N
  uint8_t *pPkcBufferRand = pPkcBufferN + pkcByteLenKey + MCUXCLRSA_PKC_WORDSIZE;
  uint8_t *pPkcBufferPb = pPkcBufferRand + blindAlignLen;
  uint8_t *pPkcBufferQb = pPkcBufferPb + blindedPrimeAlignLen;
  uint8_t *pPkcBufferNb = pPkcBufferQb + blindedPrimeAlignLen;
  uint8_t *pPkcBufferRandSquare = pPkcBufferNb + blindedModAlignLen;

  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS2_SETLENGTH(pkcByteLenPrime, blindAlignLen);

  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_N] = MCUXCLPKC_PTR2OFFSET(pPkcBufferN);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_RAND] = MCUXCLPKC_PTR2OFFSET(pPkcBufferRand);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_P_B] = MCUXCLPKC_PTR2OFFSET(pPkcBufferPb);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_Q_B] = MCUXCLPKC_PTR2OFFSET(pPkcBufferQb);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_N_B] = MCUXCLPKC_PTR2OFFSET(pPkcBufferNb);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_RAND_SQUARE] = MCUXCLPKC_PTR2OFFSET(pPkcBufferRandSquare);

  /* Generate random number r32 used for blinding and set LSB to 1, to ensure it is odd and non-null */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pPkcBufferRand is 32-bit aligned.")
  uint32_t *pR32 = (uint32_t *) pPkcBufferRand;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word));
  MCUX_CSSL_FP_FUNCTION_CALL(random32, mcuxClPrng_generate_word());
  pR32[0] = random32 | 0x1u;
  pR32[1] = 0u;

  /* Compute pb = p * r32 and qb = q * r32 */
  MCUXCLPKC_FP_CALCFUP(mcuxClRsa_Util_KeyGeneration_Plain_BlindPQ_FUP,
          mcuxClRsa_Util_KeyGeneration_Plain_BlindPQ_FUP_LEN);

  /* Compute blinded modulus: Nb = pb * qb and square of blinding value:  (r32)^2 */
  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS1_SETLENGTH(0u, blindAlignLen);
  MCUXCLPKC_PS2_SETLENGTH(blindedPrimeAlignLen, blindedPrimeAlignLen);
  MCUXCLPKC_FP_CALCFUP(mcuxClRsa_Util_KeyGeneration_Plain_ComputeNbAndRandSquare_FUP,
          mcuxClRsa_Util_KeyGeneration_Plain_ComputeNbAndRandSquare_FUP_LEN);

  /* Compute modulus N = Nb / ((r32)^2). Note that (r32)^2 is non-null and odd. */
  MCUXCLMATH_FP_EXACTDIVIDEODD(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_N,
                              MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_N_B,
                              MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_RAND_SQUARE,
                              MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_P_B /* as temp buffer */,
                              blindedModAlignLen,
                              blindSquaredAlignLen);

  MCUXCLPKC_WAITFORFINISH();

  /*
   * Write public key (computed n, e) to the buffer pointed by pPubData.
   * This buffer contains RSA key (mcuxClRsa_KeyData_Plain_t data type, i.e. key entries)
   * followed by the key data, i.e.: n, e.
   * Key entries stored in big-endian byte order (copy with reverse order).
   *
   * Used functions: MCUXCLKEY_STORE_FP (to export n and e).
   */
  mcuxClRsa_KeyData_Plain_t rsaPubKeySrc = {
                              .modulus.pKeyEntryData = pPkcBufferN,
                              .modulus.keyEntryLength = byteLenKey,
                              .exponent.pKeyEntryData = pPkcBufferE,
                              .exponent.keyEntryLength = byteLenE
  };
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(pubKey));
  MCUXCLKEY_STORE_FP(pSession, pubKey, (uint8_t*)&rsaPubKeySrc, 0u);  // RSA Key_store function always returns OK

  /*
   * Write RSA plain key (d, n) to the buffer pointed by pPrivData.
   * This buffer contains RSA key (mcuxClRsa_KeyData_Plain_t data type, i.e.: key entries)
   * followed by the key data, i.e.: n, d.
   * Key entries stored in big-endian byte order (copy with reverse order).
   *
   * Used functions: MCUXCLKEY_STORE_FP
   */
  mcuxClRsa_KeyData_Plain_t rsaPrivKeySrc = {
                              .modulus.pKeyEntryData = pPkcBufferN,
                              .modulus.keyEntryLength = byteLenKey,
                              .exponent.pKeyEntryData = d.pKeyEntryData,
                              .exponent.keyEntryLength = d.keyEntryLength
  };
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_STORE_FP_CALLED(privKey));
  MCUXCLKEY_STORE_FP(pSession, privKey, (uint8_t*)&rsaPrivKeySrc, 0u);  // RSA Key_store function always returns OK

  /* Create link between private and public key handles */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_linkKeyPair(pSession, privKey, pubKey));

  /* Free PKC WA.
   * If MCUXCLSESSION_SECURITYOPTIONS_VERIFY_GENERATED_KEY_MASK is set, PKC WA will be re-used by the key verification.
   * Otherwise, the maximum PKC WA that has been used in mcuxClRsa_Util_KeyGeneration_Plain and its subfunctions will be cleared by mcuxClRsa_VerifyKey. */
  mcuxClSession_freeWords_pkcWa(pSession, pkcWaSizeWord);

  /* If MCUXCLSESSION_SECURITYOPTIONS_VERIFY_GENERATED_KEY_MASK is set, it will verify the generated private key.
   * Otherwise it will only clear PKC workarea. */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("pPublicExponent is only dereferenced in CRT-case, so false positive here in Plain case")
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_VerifyKey(
          pSession,
          privKey,
          pubKey,
          MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
          NULL, /* Unused for plain keys */
          MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
          pPkcWorkarea));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  /* Release PKC and exit */
  MCUXCLPKC_FP_DEINITIALIZE_RELEASE(pSession);
  mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_Util_KeyGeneration_Plain,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_Util_KeyGeneration_Init_PlainKey),
    MCUXCLPKC_FP_CALLED_REQUEST_INITIALIZE,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportBigEndianToPkc),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_GenerateProbablePrime),
    loopCounter * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_GenerateProbablePrime),
    loopCounter * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_TestPQDistance),
    loopCounter * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_ComputeD),
    2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ExactDivideOdd),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_linkKeyPair),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_VerifyKey),
    MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE);
}
