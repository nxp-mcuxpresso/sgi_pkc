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

/** @file  mcuxClRsa_Mgf1.c
 *  @brief mcuxClRsa: function, which is called to execute the mask generation function MGF1 of PKCS #1 v2.2.
 */

#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClHash.h>
#include <internal/mcuxClHash_Internal.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxCsslDataIntegrity.h>

#include <mcuxClRsa.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_mgf1)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_mgf1(
  mcuxClSession_Handle_t     pSession,
  mcuxClHash_Algo_t          pHashAlgo,
  const uint8_t *           pInput,
  const uint32_t            inputLength,
  const uint32_t            outputLength,
  uint8_t *                 pOutput)
{

  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_mgf1);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(outputLength, 1u, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inputLength, 1u, MCUXCLRSA_MAX_MODLEN, MCUXCLRSA_STATUS_INVALID_INPUT)

  const uint32_t hLen = pHashAlgo->hashSize;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(hLen, MCUXCLRSA_HASH_MIN_SIZE, MCUXCLRSA_HASH_MAX_SIZE, MCUXCLRSA_STATUS_INVALID_INPUT)

  /* Update PKC workarea */
  const uint32_t wordSizePkcWa = (MCUXCLRSA_INTERNAL_MGF1_WAPKC_SIZE(inputLength, hLen) / (sizeof(uint32_t)));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_pkcWa));
  MCUX_CSSL_FP_FUNCTION_CALL(uint8_t*, pPkcWorkarea, mcuxClSession_allocateWords_pkcWa(pSession, wordSizePkcWa));

  /* Pointer to the hash output */
  uint8_t * pHashOutput = pPkcWorkarea;

  /* Set up hash input */
  uint8_t * pHashInput = pHashOutput + hLen;

  /* Balance DI for call to mcuxClMemory_copy_int */
  MCUX_CSSL_DI_RECORD(memCopyHashInput, pHashInput);
  MCUX_CSSL_DI_RECORD(memCopyHashInput, pInput);
  MCUX_CSSL_DI_RECORD(memCopyHashInput, inputLength);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(pHashInput, pInput, inputLength));

  /* counter = UPPER_BOUND(outputLength / pHashAlgo->hashSize) */
  const uint32_t mxCounter = ((outputLength + hLen - 1U) / hLen);

  /* concatenated size of T */
  uint32_t tLen = 0U;

  for(uint32_t counter = 0U; counter < mxCounter; counter++)
  {
    /* Convert counter to a big endian byte string C of length 4. */
    pHashInput[inputLength]      = (uint8_t)((counter >> 24) & 0xFFu);
    pHashInput[inputLength + 1U] = (uint8_t)((counter >> 16) & 0xFFu);
    pHashInput[inputLength + 2U] = (uint8_t)((counter >> 8) & 0xFFu);
    pHashInput[inputLength + 3U] = (uint8_t)(counter & 0xFFu);

    /* Append Hash(pInput || C) to T */

    /* Compute Hash */
    uint32_t hashOutputSize = 0u;

    MCUXCLBUFFER_INIT(pHashInputBuf, pSession, pHashInput, inputLength);
    MCUXCLBUFFER_INIT(pHashOutputBuf, pSession, pHashOutput, hLen);
    MCUX_CSSL_FP_FUNCTION_CALL(hash_result, mcuxClHash_compute(pSession,
                                                             pHashAlgo,
                                                             pHashInputBuf,
                                                             inputLength + 4U,
                                                             pHashOutputBuf,
                                                             &hashOutputSize) );

    /* mcuxClHash_compute is an public function. Hence check session error/fault and handle accordingly */
    MCUXCLSESSION_CHECK_ERROR_FAULT(pSession, hash_result);

    /* Concatenate the hash of the seed pInput and C to the T */
    uint32_t concatenateLen = (tLen + hLen > outputLength) ? (outputLength - tLen) : hLen;
    /* Balance DI for call to mcuxClMemory_copy_int */
    MCUX_CSSL_DI_RECORD(memCopyOutput, pOutput + tLen);
    MCUX_CSSL_DI_RECORD(memCopyOutput, pHashOutput);
    MCUX_CSSL_DI_RECORD(memCopyOutput, concatenateLen);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(pOutput + tLen, pHashOutput, concatenateLen));

    tLen += concatenateLen;
  }

  mcuxClSession_freeWords_pkcWa(pSession, wordSizePkcWa);

/* Check define outside of macro so the MISRA rule 20.6 does not get violated */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_mgf1,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) * mxCounter);
}
