/*--------------------------------------------------------------------------*/
/* Copyright 2020-2026 NXP                                                  */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
/*--------------------------------------------------------------------------*/

/**
 * @example mcuxClCipherModes_Ecb_Aes128_Multipart_PaddingISO_example.c
 * @brief   Example for the mcuxClCipherModes component
 */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClAes.h> // Interface to AES-related definitions and types
#include <mcuxClCipher.h> // Interface to the entire mcuxClCipher component
#include <mcuxClCipherModes.h> // Interface to the entire mcuxClCipherModes component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClBuffer.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

static const uint8_t plain[62] = {
    0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U,
    0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U,
    0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U,
    0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U,
    0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU,
    0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
    0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU,
    0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U
};

/* ECB encrypted data */
static const uint8_t encryptedRef[64] = {
    0x82U, 0x4fU, 0x7aU, 0xb3U, 0xdfU, 0x5eU, 0x73U, 0x42U,
    0x35U, 0xbbU, 0xcfU, 0xeaU, 0xdaU, 0x7eU, 0x74U, 0xc1U,
    0x7aU, 0x08U, 0x34U, 0x2dU, 0x49U, 0xacU, 0xadU, 0x72U,
    0x0eU, 0xb3U, 0x23U, 0xb6U, 0x49U, 0x42U, 0x01U, 0xf2U,
    0x06U, 0x87U, 0x58U, 0xcfU, 0x41U, 0xb0U, 0xd6U, 0x63U,
    0x66U, 0x50U, 0x1bU, 0xe8U, 0x05U, 0x66U, 0xa8U, 0xfbU,
    0x74U, 0x08U, 0xbfU, 0x32U, 0x9bU, 0x71U, 0xe2U, 0xb7U,
    0x2bU, 0x3bU, 0x11U, 0xcaU, 0x08U, 0x46U, 0x25U, 0x4fU
};

static const uint8_t keyBytes[16] = {
    0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
    0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U, 0x79U, 0x7AU,
};

MCUXCLEXAMPLE_FUNCTION(mcuxClCipherModes_Ecb_Aes128_Multipart_PaddingISO_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

#define MCUXCLCIPHERMODES_CPU_WA MCUXCLCIPHER_AES_PROCESS_CPU_WA_BUFFER_SIZE
#define MCUXCLCIPHERMODES_CONTEXT_SIZE MCUXCLCIPHER_AES_CONTEXT_SIZE


  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHERMODES_CPU_WA, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0U);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status, ki_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ key,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData:                   */ keyBytes,
    /* uint32_t keyDataLength:               */ sizeof(keyBytes))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) || (MCUXCLKEY_STATUS_OK != ki_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Encryption                                                             */
  /**************************************************************************/

  uint32_t outLength = 0U;
  uint32_t encryptedSize = 0U;
  uint8_t encryptedData[sizeof(encryptedRef)];

  /* Create a buffer for the context */
  ALIGNED uint8_t ctxBuf[MCUXCLCIPHERMODES_CONTEXT_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClCipher_Context_t * const ctx = (mcuxClCipher_Context_t *) ctxBuf;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ei_status, ei_token, mcuxClCipher_init_encrypt(
    /* mcuxClSession_Handle_t session:         */ session,
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    /* const mcuxClKey_Handle_t key:           */ key,
    /* mcuxClCipher_Mode_t mode:               */ mcuxClCipher_Mode_AES_ECB_PaddingISO9797_1_Method2,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* mcuxCl_InputBuffer_t pIv:               */ NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    /* uint32_t ivLength:                     */ 0)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_init_encrypt) != ei_token) || (MCUXCLCIPHER_STATUS_OK != ei_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_RO(plainBuf, session, plain, sizeof(plain));
  MCUXCLBUFFER_INIT(encryptedDataBuf, session, encryptedData, sizeof(encryptedData));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ep1_status, ep1_token, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_encrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:               */ plainBuf,
    /* uint32_t inLength:                     */ sizeof(plain) / 2U,
    /* mcuxCl_Buffer_t pOut:                   */ encryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != ep1_token) || (MCUXCLCIPHER_STATUS_OK != ep1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  encryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUXCLBUFFER_UPDATE(plainBuf, sizeof(plain)/2U);
  MCUXCLBUFFER_UPDATE(encryptedDataBuf, encryptedSize);
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ep2_status, ep2_token, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_encrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:               */ plainBuf,
    /* uint32_t inLength:                     */ sizeof(plain) - sizeof(plain) / 2U,
    /* mcuxCl_Buffer_t pOut:                   */ encryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != ep2_token) || (MCUXCLCIPHER_STATUS_OK != ep2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  encryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  /* Using MCUXCLBUFFER_SET instead of MCUXCLBUFFER_UPDATE is needed to properly advance the buffer to the correct offset */
  MCUXCLBUFFER_SET(encryptedDataBuf, &encryptedData[encryptedSize], sizeof(encryptedData) /* unused */);
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ef_status, ef_token, mcuxClCipher_finish(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_encrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_Buffer_t pOut:                   */ encryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_finish) != ef_token) || (MCUXCLCIPHER_STATUS_OK != ef_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  encryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  /**************************************************************************/
  /* Decryption                                                             */
  /**************************************************************************/

  uint32_t decryptedSize = 0U;
  uint8_t decryptedData[sizeof(plain)];

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(di_status, di_token, mcuxClCipher_init_decrypt(
    /* mcuxClSession_Handle_t session:         */ session,
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    /* const mcuxClKey_Handle_t key:           */ key,
    /* mcuxClCipher_Mode_t mode:               */ mcuxClCipher_Mode_AES_ECB_PaddingISO9797_1_Method2,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* mcuxCl_InputBuffer_t pIv:               */ NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    /* uint32_t ivLength:                     */ 0)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_init_decrypt) != di_token) || (MCUXCLCIPHER_STATUS_OK != di_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Process again from the beginning of encryptedDataBuf */
  MCUXCLBUFFER_SET(encryptedDataBuf, encryptedData, sizeof(encryptedData) /* unused */);
  MCUXCLBUFFER_INIT(decryptedDataBuf, session, decryptedData, sizeof(decryptedData));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dp1_status, dp1_token, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_decrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:               */ (mcuxCl_InputBuffer_t)encryptedDataBuf,
    /* uint32_t inLength:                     */ encryptedSize / 3U,
    /* mcuxCl_Buffer_t pOut:                   */ decryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != dp1_token) || (MCUXCLCIPHER_STATUS_OK != dp1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  decryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUXCLBUFFER_UPDATE(encryptedDataBuf, encryptedSize / 3U);
  MCUXCLBUFFER_UPDATE(decryptedDataBuf, decryptedSize);
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dp2_status, dp2_token, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_decrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:               */ (mcuxCl_InputBuffer_t)encryptedDataBuf,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not wrap")
    /* uint32_t inLength:                     */ encryptedSize - encryptedSize / 3U,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    /* mcuxCl_Buffer_t pOut:                   */ decryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != dp2_token) || (MCUXCLCIPHER_STATUS_OK != dp2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  decryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  /* Using MCUXCLBUFFER_SET instead of MCUXCLBUFFER_UPDATE is needed to properly advance the buffer to the correct offset */
  MCUXCLBUFFER_SET(decryptedDataBuf, &decryptedData[decryptedSize], sizeof(decryptedData) /* unused */);
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(df_status, df_token, mcuxClCipher_finish(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_decrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_Buffer_t pOut:                   */ decryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_finish) != df_token) || (MCUXCLCIPHER_STATUS_OK != df_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  decryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  /**************************************************************************/
  /* Destroy the current session                                            */
  /**************************************************************************/

  if(!mcuxClExample_Session_Clean(session))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }


  /**************************************************************************/
  /* Verification                                                           */
  /**************************************************************************/

  if(sizeof(encryptedRef) != encryptedSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(!mcuxClCore_assertEqual(encryptedRef, encryptedData, sizeof(encryptedRef)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(sizeof(plain) != decryptedSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(!mcuxClCore_assertEqual(plain, decryptedData, sizeof(plain)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
