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

/** @file  mcuxClRsa_PssEncode.c
 *  @brief mcuxClRsa: function, which is called to execute EMSA-PSS-ENCODE
 */

#include <stdint.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClBuffer.h>
#include <mcuxClRsa.h>

#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClRandom_Internal_Functions.h>

#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_pssEncode, mcuxClRsa_PadVerModeEngine_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_pssEncode(
  mcuxClSession_Handle_t       pSession,
  mcuxCl_InputBuffer_t         pInput,
  const uint32_t              inputLength UNUSED_PARAM,
  uint8_t *                   pVerificationInput UNUSED_PARAM,
  mcuxClHash_Algo_t            pHashAlgo,
  mcuxCl_InputBuffer_t         pLabel UNUSED_PARAM,
  const uint32_t              saltlabelLength,
  const uint32_t              keyBitLength,
  const uint32_t              options UNUSED_PARAM,
  mcuxCl_Buffer_t              pOutput,
  uint32_t * const            pOutLength UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_pssEncode);

  /* Length of the encoded message. */
  const uint32_t emLen = keyBitLength / 8U; /* only byte-level granularity of keys is supported, thus keyBitLength is a multiple of 8 */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(emLen, MCUXCLRSA_MIN_MODLEN, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)
  /* Length of padding with 8 zero bytes. */
  const uint32_t padding1Length = MCUXCLRSA_PSS_PADDING1_LEN;
  /* Length of the output of hash function. */
  const uint32_t hLen = pHashAlgo->hashSize;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(hLen, MCUXCLRSA_HASH_MIN_SIZE, MCUXCLRSA_HASH_MAX_SIZE, MCUXCLRSA_STATUS_INVALID_INPUT)
  /* Length of the EMSA-PSS salt. */
  const uint32_t sLen = saltlabelLength;

  /* Step 3: If emLen < hLen + sLen + 2, output "encoding error" and stop. */
  /*
   * Here: If BYTE_LENGTH(keyBitLength) < (pHashAlgo->hashSize + saltlabelLength + 2)
   *  return MCUXCLRSA_STATUS_INVALID_INPUT else continue operation.
   *
   * Note: The check in Step 3 is moved here at the top of the function, since all lengths are already known.
   * Thus, no unnecessary hashing is performed in case of invalid input.
   * In addition, this ensures that this check is done before any operation on checked arguments is performed.
   *
   * Note: Additional checks on salt-length for FIPS 186-4 compliance are also done here.
   */

  if((hLen < sLen) || (emLen < (hLen + sLen + 2u)) || ((1024u == keyBitLength) && (512u == (8u * hLen)) && ((hLen - 2u) < sLen)))
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLRSA_STATUS_INVALID_INPUT);
  }

  /* Length of M' */
  const uint32_t mprimLen = padding1Length + hLen + sLen;
  /* Length of DB (and maskedDB). */
  const uint32_t dbLen = emLen - hLen - 1u;
  /* Length of PS padding */
  const uint32_t padding2Length = emLen - hLen - sLen - 2u;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(padding2Length, 0u, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)
  /* Length of PS padding plus one 0x01 byte */
  const uint32_t padding3Length = padding2Length + 1u;

  /*
   * Set buffers in the PKC workarea
   * M' = | M'= (padding | mHash | salt) |
   */
  const uint32_t wordSizePkcWa = MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WAPKC_SIZE_WO_MGF1(emLen) / sizeof(uint32_t);
  uint8_t *pMprim = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, wordSizePkcWa);

  /* Pointer to the buffer for the mHash in the M'*/
  uint8_t *pMHash = pMprim + padding1Length;
  /* Pointer to the buffer for the salt in the M'*/
  uint8_t *pSalt = pMHash + hLen;

  /* Pointer to the encoded message */
  /* Extract plain pointer from buffer type (this buffer has been created in internal memory by the calling function, for compatibility purposes) */
  uint8_t *pEm = MCUXCLBUFFER_GET(pOutput);
  /* Pointer to the hash */
  uint8_t *pH = pEm + dbLen;

  /* Note: Step 1 from EMSA-PSS-VERIFY in PKCS #1 v2.2 can be avoided because messageLength
   * of function mcuxClRsa_sign is of type uint32_t and thus limited to 32 bits.
   */

  /* Step 2: Let mHash = Hash(M), an octet string of length hLen.
   * Copy pInput to buffer mHash */
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pInput);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pMHash);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, hLen);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pInput, 0u, pMHash, hLen));

  /* Step 4: Generate a random octet string salt of length sLen; if sLen = 0, then salt is the empty string. */
  MCUXCLBUFFER_INIT(pBufSalt, NULL, pSalt, sLen);
  MCUX_CSSL_DI_RECORD(randomGenerateParams, pSession);
  MCUX_CSSL_DI_RECORD(randomGenerateParams, pBufSalt);
  MCUX_CSSL_DI_RECORD(randomGenerateParams, sLen);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_generate_internal(pSession, pBufSalt, sLen, NULL));

  /* Step 5: Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt; */
  /* M' is an octet string of length 8 + hLen + sLen with eight initial zero octets. */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_mPrim, pMprim);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_mPrim, padding1Length);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(pMprim, padding1Length));

  /* Step 6: Let H = Hash(M'), an octet string of length hLen. */
  uint32_t hashOutputSize = 0u;

  MCUXCLBUFFER_INIT_RO(pMprimBuf, NULL, pMprim, padding1Length);
  MCUXCLBUFFER_INIT(pHBuf, NULL, pH, hLen);
  MCUX_CSSL_FP_FUNCTION_CALL(hash_result_2, mcuxClHash_compute(pSession,
                                                             pHashAlgo,
                                                             pMprimBuf,
                                                             mprimLen,
                                                             pHBuf,
                                                             &hashOutputSize
                                                             ));
  /* mcuxClHash_compute is an public function. Hence check session error/fault and handle accordingly */
  MCUXCLSESSION_CHECK_ERROR_FAULT(pSession, hash_result_2);

  /* Step 9: Let dbMask = MGF(H, emLen - hLen - 1). */
  /* Note: Step 9 has been moved up. Compute the MGF first and store the resulting mask directly in the
   * output buffer, where it is adjusted afterwards. This saves temporary buffer space and copy operations.
   */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_mgf1(pSession, pHashAlgo, pH, hLen, dbLen, pEm));

  /* Step 7: Generate an octet string PS consisting of emLen - sLen - hLen - 2 zero octets. */
  /* The length of PS may be 0. */
  /* Step 8: Let DB = PS || 0x01 || salt; DB is an octet string of length emLen - hLen - 1. */
  /* Step 10:  Let maskedDB = DB \xor dbMask. */

  /* PS consists of zeros only, so the first len(PS) bytes in the output buffer can be left as
   * they are because XOR with zero does not change the values.
   * The other items in DB, 0x01 and the salt, will be XORed directly onto the output buffer.
   */

  /* XOR 0x01 to the output buffer at the corresponding position. */
  *(pEm + padding2Length) ^= 0x01u;

  /* XOR the salt to the output buffer at the corresponding positions. */
  MCUX_CSSL_DI_RECORD(memXORintParams, pEm + padding3Length);
  MCUX_CSSL_DI_RECORD(memXORintParams, pEm + padding3Length);
  MCUX_CSSL_DI_RECORD(memXORintParams, pSalt);
  MCUX_CSSL_DI_RECORD(memXORintParams, sLen);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XOR_int(pEm + padding3Length, pEm + padding3Length, pSalt, sLen));

  /* Step 11:  Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero. */
  /* Since we assume the key length to be a multiple of 8, this becomes simply the leftmost bit. */

  *(pEm) &= 0x7fu;

  /* Step 12:  Let EM = maskedDB || H || 0xbc. */

  *(pEm + emLen - 1U) = 0xbcu;

  /* Step 13:  Output EM. */
  /* Switch endianess of EM buffer in-place to little-endian byte order. */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("the pEm PKC buffer is CPU word aligned.")
  MCUXCLPKC_FP_SWITCHENDIANNESS((uint32_t *) pEm, emLen);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  /************************************************************************************************/
  /* Function exit                                                                                */
  /************************************************************************************************/
  mcuxClSession_freeWords_pkcWa(pSession, wordSizePkcWa);

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssEncode, MCUXCLRSA_STATUS_INTERNAL_ENCODE_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate_internal),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_mgf1),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XOR_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SwitchEndianness));

#undef TMP_FEATURE_ELS_RNG
}
