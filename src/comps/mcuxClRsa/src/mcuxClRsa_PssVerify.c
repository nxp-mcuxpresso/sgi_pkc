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

/** @file  mcuxClRsa_PssVerify.c
 *  @brief mcuxClRsa: function, which is called to execute EMSA-PSS-VERIFY
 */

#include <stdint.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>

#include <mcuxClBuffer.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>

#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClMemory_Internal.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_ImportExport.h>

#include <internal/mcuxClBuffer_Internal.h>

#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>


/* Define to avoid preprocessor directives inside the function exit macro,
   as this would violate the MISRA rule 20.6 otherwise. */
#define FP_RSA_PSSVERIFY_SWITCHENDIANNESS \
  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SwitchEndianness)

/* Macros to switch endianness */
#define MCUXCLRSA_INTERNAL_SWITCHENDIANNESS(ptr, length)  MCUXCLPKC_FP_SWITCHENDIANNESS(ptr, length)

/**
 * @brief This function checks the lengths of pssVerify inputs, as well as the value of the first and the last padding bytes.
 *
 * @param       keyBitLength        Key length in bit
 * @param[in]   hLen                Hash function output length
 * @param[out]  sLen                EMSA-PSS salt length
 * @param[in]   emLen               Encoded message length
 * @param[in]   pEm                 Pointer to encoded message
 *
 * @return statusCode
 * @retval MCUXCLRSA_STATUS_OK             Is returned when checks are passing.
 * @retval MCUXCLRSA_STATUS_VERIFY_FAILED  Is returned when checks are not passing.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_pssVerify_sizeAndBytes_check)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_pssVerify_sizeAndBytes_check(
  uint32_t keyBitLength,
  uint32_t hLen,
  uint32_t sLen,
  uint32_t emLen,
  uint8_t * pEm
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_pssVerify_sizeAndBytes_check);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(hLen, MCUXCLRSA_HASH_MIN_SIZE, MCUXCLRSA_HASH_MAX_SIZE, MCUXCLRSA_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(emLen, hLen + 1U, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)
  /* Step 3: If BYTE_LENGTH(keyBitLength) < (pHashAlgo->hashSize + saltlabelLength + 2)
  *  return MCUXCLRSA_STATUS_VERIFY_FAILED else continue operation. */
  /* Additional checks on salt-length for FIPS 186-4 compliance */
  /* The constraint on sLen for FIPS186.5 is always met, so no additional check is needed. In step 10, we check that the zero-padding has the expected length w.r.t. sLen. */
  /* Step 4: Check if the leftmost octet of Em (before endianness switch) has hexadecimal value 0xbc.*/
  /* Step 6: Check if 8*emLen-emBits leftmost bits (before endianness switch) equal to zero. Note that, as keyBitLength is a multiple of 8, 8 * emLen - emBits = 1 bit.*/

  if(((hLen < sLen)) || (emLen < (hLen + sLen + 2U)) || (0xbcU != *pEm) || (0U != ((pEm[emLen - 1u]) & 0x80u)))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify_sizeAndBytes_check, MCUXCLRSA_STATUS_VERIFY_FAILED);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify_sizeAndBytes_check, MCUXCLRSA_STATUS_OK);
}

  #define FP_RSA_PSSVERIFY_COMPARISON MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_compare_secure_int)

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_pssVerify, mcuxClRsa_PadVerModeEngine_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_pssVerify(
  mcuxClSession_Handle_t       pSession,
  mcuxCl_InputBuffer_t         pInput,
  const uint32_t              inputLength UNUSED_PARAM,
  uint8_t *                   pVerificationInput,
  mcuxClHash_Algo_t            pHashAlgo,
  mcuxCl_InputBuffer_t         pLabel UNUSED_PARAM,
  const uint32_t              saltlabelLength,
  const uint32_t              keyBitLength,
  const uint32_t              options,
  mcuxCl_Buffer_t              pOutput UNUSED_PARAM,
  uint32_t * const            pOutLength UNUSED_PARAM)
{

  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_pssVerify);
  (void)options;

  /* Setup session. */

  /* Length of the encoded message. */
  const uint32_t emLen = keyBitLength / 8U; /* only byte-level granularity of keys is supported, thus keyBitLength is a multiple of 8 */
  /* Length of padding with 8 zero bytes. */
  const uint32_t padding1Length = MCUXCLRSA_PSS_PADDING1_LEN;
  /* Length of the output of hash function. */
  const uint32_t hLen = pHashAlgo->hashSize;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(hLen, MCUXCLRSA_HASH_MIN_SIZE, MCUXCLRSA_HASH_MAX_SIZE, MCUXCLRSA_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(emLen, hLen + 1U, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)
  /* Length of the EMSA-PSS salt. */
  const uint32_t sLen = saltlabelLength;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(sLen, MCUXCLRSA_HASH_MIN_SIZE, MCUXCLRSA_HASH_MAX_SIZE, MCUXCLRSA_STATUS_INVALID_INPUT)
  /* Length of DB (and maskedDB). */
  const uint32_t dbLen = emLen - hLen - 1U;

  const uint16_t wordSizePkcWa = (uint16_t)(MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WAPKC_SIZE_WO_MGF1(emLen) / sizeof(uint32_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(pSession, wordSizePkcWa));

  /*
   * Set buffers in PKC workarea
   * PKC = | M'= (padding | mHash | salt) || dbMask (and DB) || H' |
   */
  /* Pointer to the encoded message */
  uint8_t *pEm = pVerificationInput;
  /* Pointer to the buffer for the M' = | padding_1 | mHash | salt | */
  uint8_t *pMprim = pPkcWorkarea;
  /* Pointer to the buffer for the mHash in the M'*/
  uint8_t *pMHash = pMprim + padding1Length;
  /* Pointer to the buffer for the salt in the M'*/
  uint8_t *pSalt = pMHash + hLen;

  /* Pointer to the buffer for the dbMask' (must be aligned to CPU word size)*/
  uint8_t *pDbMask = pSalt + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sLen);
  /* Pointer to the buffer for the H' */
  uint8_t *pHprim = pDbMask + dbLen;

  const uint32_t mprimLen = padding1Length + hLen + sLen;

  /* Step 2: Let mHash = Hash(M), an octet string of length hLen.
   * Copy pInput to buffer mHash. */
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pMHash);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, hLen);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pInput, 0u, pMHash, hLen));

  /* Steps 3, 4 and 6:
   * - Check sizes, including for FIPS compliance
   * - Check if the rightmost octet of EM has hexadecimal value 0xbc
   * - Check if the leftmost 8*emLen-emBits bits of maskedDB are equal to zero */

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pssVerify_sizeAndBytes_check));
  MCUX_CSSL_FP_FUNCTION_CALL(internalRetStatus, mcuxClRsa_pssVerify_sizeAndBytes_check(keyBitLength, hLen, sLen, emLen, pEm));
  if(MCUXCLRSA_STATUS_OK != internalRetStatus)
  {
    /* Normal exit with MCUXCLRSA_STATUS_VERIFY_FAILED */
    mcuxClSession_freeWords_pkcWa(pSession, wordSizePkcWa);

    MCUX_CSSL_DI_EXPUNGE(verifyPadMsg, pVerificationInput);
    MCUX_CSSL_DI_RECORD(verifyRetCode, MCUXCLRSA_STATUS_VERIFY_FAILED);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, internalRetStatus,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
  }

  /* Switch endianess of EM buffer to big-endian byte order in place */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("the pEm PKC buffer is CPU word aligned.")
  MCUXCLRSA_INTERNAL_SWITCHENDIANNESS((uint32_t *) pEm, emLen);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  /* Step 5: Let maskedDB be the leftmost emLen-hLen-1 octets of EM and let H be the next hLen octets. */
  uint8_t *maskedDB = pEm;
  uint8_t *pH = pEm + dbLen;
  MCUX_CSSL_DI_RECORD(verifyMaskedDB, (uint32_t) pEm);
  MCUX_CSSL_DI_RECORD(verifyH, (uint32_t) pEm + dbLen);

  /* Step 7: dbMask = MGF(H, BYTE_LENGTH(keyBitLength) - pHashAlgo->hashSize - 1) */

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_mgf1(pSession, pHashAlgo, pH, hLen, dbLen, pDbMask));

  /* Step 8: DB = pOutput(0 : BYTE_LENGTH(keyBitLength) - pHashAlgo->hashSize - 1) XOR dbMask.*/
  uint8_t *pDB = pDbMask; // reuse the space of DbMask
  MCUX_CSSL_DI_RECORD(mcuxClMemory_XOR_int, pDB);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_XOR_int, maskedDB);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_XOR_int, pDbMask);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_XOR_int, dbLen);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XOR_int(pDB, maskedDB, pDbMask, dbLen));
  MCUX_CSSL_DI_EXPUNGE(verifyMaskedDB, (uint32_t) maskedDB);

  /* Step 9: Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero. */
  pDB[0] &= 0x7Fu;

  /* Step 10 */
  /* Check (DB(0 : BYTE_LENGTH(keyBitLength) - pHashAlgo->hashSize - saltlabelLength - 2) == [0x00, ..., 0x00])
   * and that (DB(BYTE_LENGTH(keyBitLength) - pHashAlgo->hashSize - saltlabelLength - 1) == 0x01) ? */
  uint32_t counterZeros = 0u;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(emLen, (hLen + sLen + 2u), MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)
  const uint32_t padding2Length = emLen - hLen - sLen - 2u;
  MCUX_CSSL_FP_LOOP_DECL(loop2);
  for(uint32_t i = 0u; i < padding2Length; ++i)
  {
    if(0u == pDB[i])
    {
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(counterZeros, 0u, padding2Length, MCUXCLRSA_STATUS_INVALID_INPUT)
      ++counterZeros;
    }
    MCUX_CSSL_FP_LOOP_ITERATION(loop2);
    MCUX_CSSL_DI_RECORD(verifyPaddingLoop, 1u);
  }
  if((counterZeros != padding2Length) || (0x01u != pDB[padding2Length]))
  {
    /* Normal exit with MCUXCLRSA_STATUS_VERIFY_FAILED */
    mcuxClSession_freeWords_pkcWa(pSession, wordSizePkcWa);

    MCUX_CSSL_DI_EXPUNGE(verifyPadMsg, (uint32_t) pVerificationInput);
    MCUX_CSSL_DI_EXPUNGE(verifyH, (uint32_t) pH);
    MCUX_CSSL_DI_EXPUNGE(verifyPaddingLoop, padding2Length);
    MCUX_CSSL_DI_RECORD(verifyRetCode, MCUXCLRSA_STATUS_VERIFY_FAILED);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_VERIFY_FAILED,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
          FP_RSA_PSSVERIFY_SWITCHENDIANNESS,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_mgf1),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XOR_int),
          MCUX_CSSL_FP_LOOP_ITERATIONS(loop2, padding2Length));
  }

  /* Step 11: Copy salt to mPrime buffer */
  MCUX_CSSL_DI_RECORD(memCopySalt, pSalt);
  MCUX_CSSL_DI_RECORD(memCopySalt, pDB + dbLen);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(pSalt, pDB + dbLen - sLen, sLen));

  /* Step 12 */
  /* mPrime = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 || mHash || DB(BYTE_LENGTH(keyBitLength) - saltlabelLength: BYTE_LENGTH(keyBitLength))] */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_mPrim, pMprim);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_mPrim, padding1Length);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(pMprim, padding1Length));

  /* Step 13: HPrime = Hash(mPrime) */
  uint32_t hashOutputSize = 0u;
  MCUXCLBUFFER_INIT_RO(pMprimBuf, NULL, pMprim, padding1Length);
  MCUXCLBUFFER_INIT(pHprimBuf, NULL, pHprim, hLen);
  MCUX_CSSL_FP_FUNCTION_CALL(
    hash_result_2,
    mcuxClHash_compute(pSession, pHashAlgo, pMprimBuf, mprimLen, pHprimBuf, &hashOutputSize)
  );
  /* mcuxClHash_compute is an public function. Hence check session error/fault and handle accordingly */
  MCUXCLSESSION_CHECK_ERROR_FAULT(pSession, hash_result_2);

  /* Step 14 verify5 = (HPrime == H) ? true : false. */

  /* DI: pH has been recorded before */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_compare_secure_int, pHprim);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_compare_secure_int, hLen);

  mcuxClRsa_Status_t pssVerifyStatus1 = MCUXCLRSA_STATUS_FAULT_ATTACK;
  MCUX_CSSL_FP_FUNCTION_CALL(compare_result, mcuxClMemory_compare_secure_int(pH, pHprim, hLen));
  if (MCUXCLMEMORY_STATUS_EQUAL == compare_result)
  {
    pssVerifyStatus1 = MCUXCLRSA_STATUS_VERIFY_OK;
  }
  else if (MCUXCLMEMORY_STATUS_NOT_EQUAL == compare_result)
  {
    pssVerifyStatus1 = MCUXCLRSA_STATUS_VERIFY_FAILED;
  }
  else
  {
    MCUXCLSESSION_FAULT(pSession, MCUXCLRSA_STATUS_FAULT_ATTACK);
  }


  /* Protect VERIFY_OK and VERIFY_FAILED only. Functional errors or fault attack are not protected.*/
  MCUX_CSSL_DI_RECORD(verifyRetCode, pssVerifyStatus1);

  /************************************************************************************************/
  /* Function exit                                                                                */
  /************************************************************************************************/
  mcuxClSession_freeWords_pkcWa(pSession, wordSizePkcWa);

  MCUX_CSSL_DI_EXPUNGE(verifyPadMsg, (uint32_t) pVerificationInput);
  MCUX_CSSL_DI_EXPUNGE(verifyPaddingLoop, padding2Length);

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, pssVerifyStatus1,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
    FP_RSA_PSSVERIFY_SWITCHENDIANNESS,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_mgf1),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XOR_int),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop2, padding2Length),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute),
    FP_RSA_PSSVERIFY_COMPARISON
  );

#undef FP_RSA_PSSVERIFY_COMPARISON

}
