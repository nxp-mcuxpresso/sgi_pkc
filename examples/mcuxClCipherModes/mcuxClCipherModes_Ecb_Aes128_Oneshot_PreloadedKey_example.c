/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @example mcuxClCipherModes_Ecb_Aes128_Oneshot_PreloadedKey_example.c
 * @brief   Example for the mcuxClCipherModes component
 */

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

static const uint8_t plain[64] = {
    0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U,
    0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U,
    0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U,
    0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U,
    0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU,
    0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
    0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU,
    0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U, 0x73U,
};

/* ECB encrypted data */
static const uint8_t encryptedRef[64] = {
    0x82U, 0x4FU, 0x7AU, 0xB3U, 0xDFU, 0x5EU, 0x73U, 0x42U,
    0x35U, 0xBBU, 0xCFU, 0xEAU, 0xDAU, 0x7EU, 0x74U, 0xC1U,
    0x7AU, 0x08U, 0x34U, 0x2DU, 0x49U, 0xACU, 0xADU, 0x72U,
    0x0EU, 0xB3U, 0x23U, 0xB6U, 0x49U, 0x42U, 0x01U, 0xF2U,
    0x06U, 0x87U, 0x58U, 0xCFU, 0x41U, 0xB0U, 0xD6U, 0x63U,
    0x66U, 0x50U, 0x1BU, 0xE8U, 0x05U, 0x66U, 0xA8U, 0xFBU,
    0xA9U, 0xC3U, 0x3FU, 0x14U, 0xCAU, 0x96U, 0xB0U, 0x5CU,
    0xBFU, 0x0EU, 0x0AU, 0x07U, 0x90U, 0xA9U, 0x1BU, 0xBAU
};

static const uint8_t keyBytes[MCUXCLAES_AES128_KEY_SIZE] = {
    0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
    0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U, 0x79U, 0x7AU,
};

MCUXCLEXAMPLE_FUNCTION(mcuxClCipherModes_Ecb_Aes128_Oneshot_PreloadedKey_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

#define MCUXCLCIPHERMODES_CPU_WA MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHER_AES_ENCRYPT_CPU_WA_BUFFER_SIZE, MCUXCLCIPHER_AES_DECRYPT_CPU_WA_BUFFER_SIZE)

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_LOADCOPRO_CPU_WA_SIZE, MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHERMODES_CPU_WA, MCUXCLRANDOM_NCINIT_WACPU_SIZE)), 0U);

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
  /*  Key Load                                                              */
  /*  This preloads the key into an SGI key register.                       */
  /*  The key will stay in the SGI until it is explicitly flushed.          */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kl_status, kl_token, mcuxClKey_loadCopro(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ key,
    /* uint32_t options:                   */ MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_2)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != kl_token) || (MCUXCLKEY_STATUS_OK != kl_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Encryption                                                             */
  /**************************************************************************/

  uint32_t encryptedSize = 0U;
  uint8_t encryptedData[sizeof(encryptedRef)];

  MCUXCLBUFFER_INIT_RO(plainBuf, session, plain, sizeof(plain));
  MCUXCLBUFFER_INIT(encryptedDataBuf, session, encryptedData, sizeof(encryptedData));
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("Pointer is not dereferenced")
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(e_status, e_token, mcuxClCipher_encrypt(
    /* mcuxClSession_Handle_t session:           */ session,
    /* const mcuxClKey_Handle_t key:             */ key,
    /* mcuxClCipher_Mode_t mode:                 */ mcuxClCipher_Mode_AES_ECB_NoPadding,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* mcuxCl_InputBuffer_t pIv:                 */ NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    /* uint32_t ivLength:                       */ 0U,
    /* mcuxCl_InputBuffer_t pIn:                 */ plainBuf,
    /* uint32_t inLength:                       */ sizeof(plain),
    /* mcuxCl_Buffer_t pOut:                     */ encryptedDataBuf,
    /* uint32_t * const outLength:              */ &encryptedSize) /* only relevant in case of padding being used */
  );
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_encrypt) != e_token) || (MCUXCLCIPHER_STATUS_OK != e_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Decryption                                                             */
  /**************************************************************************/

  uint32_t decryptedSize = 0U;
  uint8_t decryptedData[sizeof(plain)];

  MCUXCLBUFFER_INIT(decryptedDataBuf, session, decryptedData, sizeof(decryptedData));
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("Pointer pIv is not dereferenced")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("encryptedDataBuf initialized by MCUXCLBUFFER_INIT")
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(d_status, d_token, mcuxClCipher_decrypt(
    /* mcuxClSession_Handle_t session:           */ session,
    /* const mcuxClKey_Handle_t key:             */ key,
    /* mcuxClCipher_Mode_t mode:                 */ mcuxClCipher_Mode_AES_ECB_NoPadding,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* mcuxCl_InputBuffer_t pIv:                 */ NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    /* uint32_t ivLength:                       */ 0U,
    /* const mcuxCl_Buffer_t pIn:                */ (mcuxCl_Buffer_t) encryptedDataBuf,
    /* uint32_t inLength:                       */ encryptedSize,
    /* mcuxCl_Buffer_t pOut:                     */ decryptedDataBuf,
    /* uint32_t * const outLength:              */ &decryptedSize) /* only relevant in case of padding being used/removed */
  );
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_decrypt) != d_token) || (MCUXCLCIPHER_STATUS_OK != d_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Key Flush                                                              */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf_status, kf_token, mcuxClKey_flush(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ key)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != kf_token) || (MCUXCLKEY_STATUS_OK != kf_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


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

  if(encryptedSize != sizeof(encryptedRef))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("encryptedData initialized by mcuxClCipher_encrypt")
  if(!mcuxClCore_assertEqual(encryptedRef, encryptedData, sizeof(encryptedRef)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  if(sizeof(plain) != decryptedSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("decryptedData initialized by mcuxClCipher_decrypt")
  if(!mcuxClCore_assertEqual(plain, decryptedData, sizeof(plain)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  return MCUXCLEXAMPLE_STATUS_OK;
}
