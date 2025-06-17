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

/** @file  mcuxClRsa_Pkcs1v15Encode_sign.c
 *  @brief mcuxClRsa: function, which is called to execute EMSA-PKCS1-v1_5-ENCODE
 */

#include <stdint.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClBuffer.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>

#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClMemory_Set_Internal.h>
#include <internal/mcuxClBuffer_Internal.h>

#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>
#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Macros.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_pkcs1v15Encode_sign, mcuxClRsa_PadVerModeEngine_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_pkcs1v15Encode_sign(
  mcuxClSession_Handle_t       pSession,
  mcuxCl_InputBuffer_t         pInput,
  const uint32_t              inputLength UNUSED_PARAM,
  uint8_t *                   pVerificationInput UNUSED_PARAM,
  mcuxClHash_Algo_t            pHashAlgo,
  mcuxCl_InputBuffer_t         pLabel UNUSED_PARAM,
  const uint32_t              saltlabelLength UNUSED_PARAM,
  const uint32_t              keyBitLength,
  const uint32_t              options UNUSED_PARAM,
  mcuxCl_Buffer_t              pOutput,
  uint32_t * const            pOutLength UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_pkcs1v15Encode_sign);
  /*****************************************************/
  /* Initialization                                    */
  /*****************************************************/

  /* Length of the encoded message. */
  const uint32_t emLen = keyBitLength / 8u;  /* only byte-level granularity of keys is supported, thus keyBitLength is a multiple of 8 */
  /* Length of the output of hash function. */
  const uint32_t hLength = pHashAlgo->hashSize;

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(hLength, MCUXCLRSA_HASH_MIN_SIZE, MCUXCLRSA_HASH_MAX_SIZE, MCUXCLRSA_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(emLen, MCUXCLRSA_MIN_MODLEN, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)

  /* Length of the T-padding containing the hash algorithm identifier. */
  uint8_t const * phashAlgorithmIdentifier     = pHashAlgo->pOid;
  /* Length of the T-padding DigestInfo containing the hash algorithm identifier. */
  const uint32_t hashAlgorithmIdentifierLength = pHashAlgo->oidSize;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(hashAlgorithmIdentifierLength, MCUXCLHASH_OID_SHA1_LEN, MCUXCLHASH_OID_SHA2SHA3_LEN, MCUXCLRSA_STATUS_INVALID_INPUT)

  /*****************************************************/
  /* If emLen < tLen + 11, return 'invalid input'.     */
  /*****************************************************/
  if(emLen < (hashAlgorithmIdentifierLength + hLength + 11u))
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLRSA_STATUS_INVALID_INPUT);
  }

  /*****************************************************/
  /* Prepare the padding                               */
  /*****************************************************/
  /* Number of required padding bytes */
  const uint32_t paddingLength = emLen - hashAlgorithmIdentifierLength - hLength - 3u;

  /* Setup session. */
  const uint32_t wordSizePkcWa = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(emLen) / (sizeof(uint32_t));
  uint8_t *pPkcWorkarea = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, wordSizePkcWa);

  /*
   * Set buffers in PKC workarea
   * PKC = | 0x00 || 0x01 || PS || 0x00 | T || H |
   */
  /* General pointer to encoded message at the beginning of the buffer */
  uint8_t *pEm = pPkcWorkarea;
  /* Pointer to the buffer for the padding bytes PS */
  uint8_t *pPs = pEm + 2u;
  /* Pointer to the buffer for the algorithm identifier T */
  uint8_t *pT = pPs + paddingLength + 1u;

  /* Pointer to the buffer for the hash H */
  uint8_t *pH = pT + hashAlgorithmIdentifierLength;


  /* Write 0x00 0x01 prefix */
  *(pEm)     = (uint8_t) 0x00;
  *(pEm + 1u) = (uint8_t) 0x01;

  /* Write padding bytes */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_set_int_ps, pPs);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_set_int_ps, paddingLength);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(pPs, 0xFFU, paddingLength));

  /* Write 0x00 divider */
  *(pPs + paddingLength) = (uint8_t) 0x00;

  /* Write DigestInfo T */
  MCUX_CSSL_DI_RECORD(memCopyT, pT);
  MCUX_CSSL_DI_RECORD(memCopyT, phashAlgorithmIdentifier);
  MCUX_CSSL_DI_RECORD(memCopyT, hashAlgorithmIdentifierLength);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(pT, phashAlgorithmIdentifier, hashAlgorithmIdentifierLength));

  /*****************************************************/
  /* Copy the digest                                   */
  /*****************************************************/
  /* Copy pInput to buffer at pH (located at the end of the buffer) */
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pInput);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pH);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, hLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pInput, 0u, pH, hLength));

  /*****************************************************/
  /* Prepare the encoded message for output            */
  /*****************************************************/

  /* Copy encoded message to pOutput and switch the endianness */
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_write_secure_reverse, pOutput);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_write_secure_reverse, pPkcWorkarea);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_write_secure_reverse, emLen);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write_secure_reverse(pOutput, 0u, pPkcWorkarea, emLen));

  mcuxClSession_freeWords_pkcWa(pSession, wordSizePkcWa);

  /************************************************************************************************/
  /* Function exit                                                                                */
  /************************************************************************************************/
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pkcs1v15Encode_sign, MCUXCLRSA_STATUS_INTERNAL_ENCODE_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write_secure_reverse));
}
