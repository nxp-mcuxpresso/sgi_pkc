/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

/** @file  mcuxClRsa_PrivatePlain.c
 *  @brief mcuxClRsa: implementation of RSA private plain key operation
 */

#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>

#include <mcuxClRandom.h>

#include <mcuxClRsa.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClRandom_Internal_Functions.h>
#include <internal/mcuxClPrng_Internal_Functions.h>

#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_privatePlain)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_privatePlain(
  mcuxClSession_Handle_t      pSession,
  mcuxClKey_Handle_t          key,
  uint8_t                   *pInput,
  mcuxCl_Buffer_t             pOutput)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_privatePlain);

  /************************************************************************************************/
  /* Set up the RSA key                                                                           */
  /************************************************************************************************/

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Explicitly reinterpreting opaque types of workarea-like buffer objects. Key data should be word-aligned.")
  mcuxClRsa_KeyData_Plain_t * pRsaKeyData = (mcuxClRsa_KeyData_Plain_t *) mcuxClKey_getKeyData(key);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer pRsaKeyData has compatible type and cast was valid")
  const uint32_t byteLenN = pRsaKeyData->modulus.keyEntryLength;
  const uint32_t byteLenD = pRsaKeyData->exponent.keyEntryLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()

  /* SREQI_RSA_0: DI protect the byte length of the exponent. Will be balanced in the call to mcuxClMath_SecModExp(). */
  MCUX_CSSL_DI_RECORD(privatePlain_SecModExp, byteLenD);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(byteLenN, MCUXCLRSA_MIN_MODLEN, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(byteLenD, 1u, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)

  /************************************************************************************************/
  /* Initialization                                                                               */
  /************************************************************************************************/

  /* Size definitions */
  const uint32_t blindLen = MCUXCLRSA_INTERNAL_MOD_BLINDING_SIZE;  // length in bytes of the random value used for blinding
  const uint32_t operandSize = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(byteLenN);
  const uint32_t blindAlignLen = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(blindLen);
  const uint32_t blindOperandSize = operandSize + blindAlignLen;

  const uint32_t bufferSizeR = blindOperandSize + MCUXCLRSA_PKC_WORDSIZE;  // size of the result of the exponentiation
  const uint32_t bufferSizeN = blindOperandSize + MCUXCLRSA_PKC_WORDSIZE;  // size of N + PKC word in front of the modulus buffer for NDash
  const uint32_t bufferSizeT0 = blindOperandSize + MCUXCLRSA_PKC_WORDSIZE;  // size of temp buffer T0
  const uint32_t bufferSizeT1 = blindOperandSize + MCUXCLRSA_PKC_WORDSIZE;  // size of temp buffer T1
  const uint32_t bufferSizeT2 = blindOperandSize + MCUXCLRSA_PKC_WORDSIZE;  // size of temp buffer T2
  const uint32_t bufferSizeT3 = blindOperandSize + MCUXCLRSA_PKC_WORDSIZE;  // size of temp buffer T3
  const uint32_t bufferSizeTE = 6U*MCUXCLRSA_PKC_WORDSIZE;                  // size of temp buffer TE
  const uint32_t bufferSizeRand = blindAlignLen;  // size of buffer for random multiplicative blinding

  /* Size of buffer for expTemp in PKC RAM, assuming byteLenD is not bigger than byteLenN. */
  const uint32_t bufferSizeModExpTemp = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(byteLenN + 1U);

  /* Setup session. */
  const uint32_t bufferSizeTotal = bufferSizeR + bufferSizeN + bufferSizeT0 + bufferSizeT1 + bufferSizeT2 + bufferSizeT3 + bufferSizeTE + bufferSizeRand + bufferSizeModExpTemp;
  const uint32_t pkcWaSizeWord = bufferSizeTotal / (sizeof(uint32_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint32_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(pSession, pkcWaSizeWord));

  /* Prepare buffers in PKC workarea */
  uint8_t *pR = (uint8_t *)pPkcWorkarea;
  uint8_t *pN = pR + bufferSizeR + MCUXCLRSA_PKC_WORDSIZE; // one extra PKC word for NDash in front of the modulus
  uint8_t *pT0 = pN + bufferSizeN - MCUXCLRSA_PKC_WORDSIZE;  // size of NDash is included in bufferSizeN
  uint8_t *pT1 = pT0 + bufferSizeT0;
  uint8_t *pT2 = pT1 + bufferSizeT1;
  uint8_t *pT3 = pT2 + bufferSizeT2;
  uint8_t *pTE = pT3 + bufferSizeT3;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("PKC buffers are CPU-word aligned")
  uint32_t *pBlind = (uint32_t *)pTE + (bufferSizeTE / sizeof(uint32_t));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  /* Setup UPTR table. */
  uint32_t cpuWaSizeWord = MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WACPU_SIZE_IN_WORDS(byteLenN);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint32_t*, pOperands32, mcuxClSession_allocateWords_cpuWa(pSession, cpuWaSizeWord));
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("16-bit UPTRT table is assigned in CPU workarea")
  uint16_t * pOperands = (uint16_t *) pOperands32;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_X] = MCUXCLPKC_PTR2OFFSET(pInput);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_R] = MCUXCLPKC_PTR2OFFSET(pR);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_N] = MCUXCLPKC_PTR2OFFSET(pN);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T0] = MCUXCLPKC_PTR2OFFSET(pT0);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T1] = MCUXCLPKC_PTR2OFFSET(pT1);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T2] = MCUXCLPKC_PTR2OFFSET(pT2);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T3] = MCUXCLPKC_PTR2OFFSET(pT3);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_TE] = MCUXCLPKC_PTR2OFFSET(pTE);
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_RAND] = MCUXCLPKC_PTR2OFFSET((uint8_t *)pBlind);

  /* Set UPTRT table */
  MCUXCLPKC_SETUPTRT(pOperands);

  /* Clear PKC workarea after input */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_afterInput, pInput + byteLenN);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_afterInput, MCUXCLRSA_INTERNAL_PRIVATEPLAIN_INPUT_SIZE(byteLenN) - byteLenN);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(
    mcuxClMemory_clear_int(pInput + byteLenN, MCUXCLRSA_INTERNAL_PRIVATEPLAIN_INPUT_SIZE(byteLenN) - byteLenN)
  );

  // TODO CLNS-13225: analyze what should be cleared
  MCUXCLPKC_PS1_SETLENGTH(0u, bufferSizeTotal);
  MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_R, 0u);

  uint32_t * pExpTemp = NULL;
  if (byteLenN <= MCUXCLRSA_MAX_MODLEN_EXPTEMP_IN_PKCRAM)
  {
    /* Prepare expTemp buffer in PKC workarea. It will be used in mcuxClMath_SecModExp */
    pExpTemp = pPkcWorkarea + ((bufferSizeTotal - bufferSizeModExpTemp) / sizeof(uint32_t));
  }

  /************************************************************************************************/
  /* Import in LE the modulus to target buffer in PKC workarea                                    */
  /* Check that modulus is odd; otherwise return MCUXCLRSA_STATUS_INVALID_INPUT.                   */
  /************************************************************************************************/

  /* Balance DI for the calls to MCUXCLKEY_LOAD_FP in this function - constant key specs */
  MCUX_CSSL_DI_RECORD(Key_load, MCUXCLKEY_ENCODING_SPEC_RSA_N  + MCUXCLKEY_ENCODING_SPEC_RSA_D);

  /* Import the modulus N */
  MCUX_CSSL_DI_RECORD(Key_load, key);
  MCUX_CSSL_DI_RECORD(Key_load, &pT0);
  MCUXCLPKC_WAITFORFINISH();
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(key));
  MCUXCLKEY_LOAD_FP(pSession, key, (uint8_t**)&pT0, NULL, MCUXCLKEY_ENCODING_SPEC_RSA_N );  // RSA Key_load function always returns OK

  /* Check that the modulus is odd */
  if(0U == (pT0[0u] & 0x01U))
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLRSA_STATUS_INVALID_INPUT);
  }

  /************************************************************************************************/
  /* Check that Input < Modulus;  otherwise return MCUXCLRSA_STATUS_INVALID_INPUT                  */
  /* If input is zero or one, return zero or one respectively                                     */
  /************************************************************************************************/

  MCUXCLPKC_PS1_SETLENGTH(0u, operandSize);
  MCUXCLPKC_FP_CALC_OP1_CMP(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_X, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T0);
  MCUXCLPKC_WAITFORFINISH();

  uint32_t carryFlag = MCUXCLPKC_GETCARRY();

  if(MCUXCLPKC_FLAG_CARRY != carryFlag)
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLRSA_STATUS_INVALID_INPUT);
  }

  /* Compare input to 1. Note that in order to do that in one operation, result has to be written to a temporary buffer */
  MCUXCLPKC_FP_CALC_OP1_SUB_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T2, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_X, 1u);
  MCUXCLPKC_WAITFORFINISH();

  carryFlag = MCUXCLPKC_GETCARRY();
  uint32_t zeroFlag = MCUXCLPKC_GETZERO();

  /* CARRY=1 ==> input=0, and ZERO=1 ==> input=1. In both cases, return input */
  if((MCUXCLPKC_FLAG_CARRY == carryFlag) || (MCUXCLPKC_FLAG_ZERO == zeroFlag))
  {
    MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFER_DI_BALANCED(mcuxClRsa_privatePlain, pOutput, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_X, byteLenN);

    mcuxClSession_freeWords_pkcWa(pSession, pkcWaSizeWord);
    mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);

    /* Would have been balanced in the call to mcuxClMath_SecModExp() */
    MCUX_CSSL_DI_EXPUNGE(privatePlain_SecModExp, byteLenD);

    /* Would have been balanced in the call to MCUXCLKEY_LOAD_FP */
    MCUX_CSSL_DI_EXPUNGE(Key_load, MCUXCLKEY_ENCODING_SPEC_RSA_D);

    /* DI balance the key algoId - will be RECORDed by the caller */
    MCUX_CSSL_DI_EXPUNGE(PrivatePlain_verifyKey, MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_privatePlain,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
        MCUXCLPKC_FP_CALLED_CALC_OP1_SUB_CONST,
        MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFER);
  }

  /* Generate random number used for blinding */
  pBlind[0] = mcuxClRandom_ncGenerateWord_Internal(pSession);

  /* Make it odd */
  pBlind[0] |= 0x1u;

  /* Blind modulus n */
  MCUXCLPKC_FP_CALC_OP1_MUL( MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_N /* n_b */, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_RAND /* blind */, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T0 /* n */);

  /************************************************************************************************/
  /* Prepare Montgomery parameters and convert parameters to Montgomery representation.           */
  /************************************************************************************************/

  /* Calculate Ndash of N */
  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS1_SETLENGTH(blindOperandSize, blindOperandSize);
  MCUXCLMATH_FP_NDASH(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_N, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T0);

  /* Calculate QSquared */
  MCUXCLMATH_FP_SHIFTMODULUS(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T3, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_N); //shift modulus
  MCUXCLMATH_FP_QSQUARED(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_R /* QSquared */, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T3,
      MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_N, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T0);

  /* Convert input to Montgomery representation i.e. M*QSquared mod N */
  MCUXCLPKC_FP_CALC_MC1_MM(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T2 /* Mm */, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_X /* M */,
      MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_R /* QSquared */, MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_N);

  MCUXCLPKC_WAITFORFINISH();

  /************************************************************************************************/
  /* Perform secure exponentiation.                                                               */
  /************************************************************************************************/

  /* Import the private exponent D */
  MCUX_CSSL_DI_RECORD(Key_load, key);
  MCUX_CSSL_DI_RECORD(Key_load, &pR);
  MCUX_CSSL_FP_EXPECT(MCUXCLKEY_LOAD_FP_CALLED(key));
  MCUXCLKEY_LOAD_FP(pSession, key, (uint8_t**)&pR, NULL, MCUXCLKEY_ENCODING_SPEC_RSA_D);

  /* Clear upper bytes that were not overwritten by the copy in Key_load */
  uint8_t *pUpper = pR + byteLenD;
  uint32_t lenUpper = MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(byteLenD + 1u) - byteLenD;
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, pUpper);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, lenUpper);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(pUpper, lenUpper));

  MCUXCLPKC_PS1_SETLENGTH(blindOperandSize, blindOperandSize);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(MCUXCLMATH_SECMODEXP(
    pSession,
    pExpTemp,
    byteLenD,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_R,  /* Result, and input private exponent */
    MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T2, /* Montgomery representation of base number */
    MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_N,  /* Modulus */
    MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_TE, /* Temporary buffers */
    MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T0,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T1,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_X,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T3
  ));

  /************************************************************************************************/
  /* Convert result back to normal representation and store result in pOutput.                    */
  /************************************************************************************************/
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_RemoveBlinding(
    MCUXCLPKC_PACKARGS4(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_X /* R */,
                       MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_R /* Rb */,
                       MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_N /* Nb */,
                       MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_RAND /* b */),
    MCUXCLPKC_PACKARGS2(MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T2,
                       MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_T1),
    blindOperandSize,
    blindAlignLen));

  /* Copy result to the output buffer */
  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS1_SETLENGTH(0u, operandSize);
  MCUXCLPKC_FP_SECUREEXPORTBIGENDIANFROMPKC_BUFFER_DI_BALANCED(mcuxClRsa_privatePlain, ret_SecExport, pSession,
                                                               pOutput,
                                                               MCUXCLRSA_INTERNAL_UPTRTINDEX_PRIVPLAIN_X,
                                                               byteLenN);
  if (MCUXCLPKC_STATUS_OK != ret_SecExport)
  {
      MCUXCLSESSION_FAULT(pSession, MCUXCLRSA_STATUS_FAULT_ATTACK);
  }

  /* Clear buffer pInput, which contains the output of mcuxClRsa_privatePlain in little Endian */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(pInput, byteLenN));

  /************************************************************************************************/
  /* Function exit                                                                                */
  /************************************************************************************************/

  /* DI balance the key algoId - will be RECORDed by the caller */
  MCUX_CSSL_DI_EXPUNGE(PrivatePlain_verifyKey, MCUXCLRSA_KEYTYPE_INTERNAL_PRIVATEPLAIN);

  mcuxClSession_freeWords_pkcWa(pSession, pkcWaSizeWord);
  mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_privatePlain,
      MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
      MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
      MCUXCLPKC_FP_CALLED_CALC_OP1_SUB_CONST,
      MCUXCLPKC_FP_CALLED_CALC_OP1_MUL,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_NDash),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_QSquared),
      MCUXCLPKC_FP_CALLED_CALC_MC1_MM,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_SecModExp),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_RemoveBlinding),
      MCUXCLPKC_FP_CALLED_SECUREEXPORTBIGENDIANFROMPKC_BUFFER,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal));

}

