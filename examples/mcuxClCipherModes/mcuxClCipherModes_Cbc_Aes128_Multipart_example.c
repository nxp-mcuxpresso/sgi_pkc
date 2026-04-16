/*--------------------------------------------------------------------------*/
/* Copyright 2020-2026 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/**
 * @example mcuxClCipherModes_Cbc_Aes128_Multipart_example.c
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
#include <mcuxClCore_Examples.h>
#include <mcuxClBuffer.h>
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

/* CBC encrypted data */
static const uint8_t encryptedRef[64] = {
    0xe6U, 0xd4U, 0xe7U, 0xdaU, 0x9eU, 0x63U, 0xc6U, 0x67U,
    0xfbU, 0xa0U, 0x43U, 0x2aU, 0xadU, 0x45U, 0x4bU, 0x7dU,
    0xf2U, 0xb7U, 0x91U, 0x4eU, 0x89U, 0xe1U, 0x07U, 0xe1U,
    0xa0U, 0x0eU, 0xe2U, 0x52U, 0xccU, 0xbaU, 0xbbU, 0x1fU,
    0x69U, 0x4aU, 0x00U, 0xe4U, 0x2eU, 0x89U, 0xfbU, 0x43U,
    0x79U, 0x8bU, 0x28U, 0x38U, 0x6bU, 0x7cU, 0xecU, 0x7fU,
    0x64U, 0xa0U, 0x83U, 0xedU, 0xccU, 0xc7U, 0x70U, 0x70U,
    0x2dU, 0xaeU, 0xc9U, 0x28U, 0xd7U, 0x9dU, 0x77U, 0x43U
};

static const uint8_t iv[16] = {
    0x7AU, 0x79U, 0x78U, 0x77U, 0x76U, 0x75U, 0x74U, 0x73U,
    0x72U, 0x71U, 0x70U, 0x6FU, 0x6EU, 0x6DU, 0x6CU, 0x6BU,
};

static const uint8_t keyBytes[16] = {
    0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
    0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U, 0x79U, 0x7AU,
};

MCUXCLEXAMPLE_FUNCTION(mcuxClCipherModes_Cbc_Aes128_Multipart_example)
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

  MCUXCLBUFFER_INIT_RO(ivBuf, session, iv, sizeof(iv));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ei_status, ei_token, mcuxClCipher_init_encrypt(
    /* mcuxClSession_Handle_t session:         */ session,
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    /* const mcuxClKey_Handle_t key:           */ key,
    /* mcuxClCipher_Mode_t mode:               */ mcuxClCipher_Mode_AES_CBC_NoPadding,
    /* mcuxCl_InputBuffer_t pIv:               */ ivBuf,
    /* uint32_t ivLength:                     */ sizeof(iv))
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
    /* mcuxClCipher_Mode_t mode:               */ mcuxClCipher_Mode_AES_CBC_NoPadding,
    /* mcuxCl_InputBuffer_t pIv:               */ ivBuf,
    /* uint32_t ivLength:                     */ sizeof(iv))
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
