/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

/**
 * @example mcuxClCipherModes_Cbc_Aes128_Multipart_KeyRfc3394Encoding_example.c
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


// Test vectors for RFC3394 encoding are taken from https://datatracker.ietf.org/doc/html/rfc3394.
//  The plain key data is 00112233445566778899AABBCCDDEEFF
static const uint8_t wrappedKeyData[MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE] = {
  0x64U, 0xE8U, 0xC3U, 0xF9U, 0xCEU, 0x0FU, 0x5BU, 0xA2U,
  0x63U, 0xE9U, 0x77U, 0x79U, 0x05U, 0x81U, 0x8AU, 0x2AU,
  0x93U, 0xC8U, 0x19U, 0x1EU, 0x7DU, 0x6EU, 0x8AU, 0xE7U
};

static const uint8_t kwk256Data[MCUXCLAES_AES256_KEY_SIZE] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
  0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
  0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
  0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
};

/* CBC plain data */
static const uint8_t plain[64] = {
  0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U,
  0x69U, 0x6aU, 0x6bU, 0x6cU, 0x6dU, 0x6eU, 0x6fU, 0x70U,
  0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U,
  0x6aU, 0x6bU, 0x6cU, 0x6dU, 0x6eU, 0x6fU, 0x70U, 0x71U,
  0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6aU,
  0x6bU, 0x6cU, 0x6dU, 0x6eU, 0x6fU, 0x70U, 0x71U, 0x72U,
  0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6aU, 0x6bU,
  0x6cU, 0x6dU, 0x6eU, 0x6fU, 0x70U, 0x71U, 0x72U, 0x73U
};

/* CBC IV */
static const uint8_t iv[16] = {
  0x7aU, 0x79U, 0x78U, 0x77U, 0x76U, 0x75U, 0x74U, 0x73U,
  0x72U, 0x71U, 0x70U, 0x6fU, 0x6eU, 0x6dU, 0x6cU, 0x6bU
};

/* CBC encrypted data - plain data encrypted with the expected unwrapped key material. */
static const uint8_t encryptedRef[64] = {
  0xd4U, 0x43U, 0xbcU, 0x95U, 0x30U, 0xe2U, 0x2eU, 0x9aU,
  0xcbU, 0x18U, 0x04U, 0x51U, 0xd1U, 0x08U, 0x95U, 0x80U,
  0xd6U, 0xfeU, 0x0aU, 0xe6U, 0xfbU, 0x13U, 0xbcU, 0xc1U,
  0x8cU, 0x0aU, 0x5bU, 0x8aU, 0x1dU, 0x0fU, 0xceU, 0x55U,
  0xc7U, 0xfcU, 0x1bU, 0xc6U, 0x4eU, 0x2dU, 0xf6U, 0x78U,
  0x04U, 0x4cU, 0xdfU, 0xccU, 0x82U, 0x9eU, 0x24U, 0x59U,
  0x99U, 0xcdU, 0x52U, 0xc1U, 0xb0U, 0x0eU, 0x9aU, 0x0eU,
  0xceU, 0xa4U, 0xfdU, 0x3eU, 0xbeU, 0x3eU, 0x0aU, 0xa5U
};

MCUXCLEXAMPLE_FUNCTION(mcuxClCipherModes_Cbc_Aes128_Multipart_KeyRfc3394Encoding_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_LOADCOPRO_CPU_WA_SIZE,
                                                          MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHER_AES_PROCESS_CPU_WA_BUFFER_SIZE,
                                                            MCUXCLRANDOM_NCINIT_WACPU_SIZE)), 0U);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);


  /**************************************************************************/
  /* Prepare the key-wrapping key (KWK) in the SGI                          */
  /**************************************************************************/

  uint32_t kwkDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t kwk = (mcuxClKey_Handle_t) &kwkDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki1_status, ki1_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ kwk,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes256,
    /* uint8_t * pKeyData:                   */ kwk256Data,
    /* uint32_t keyDataLength:               */ sizeof(kwk256Data))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki1_token) || (MCUXCLKEY_STATUS_OK != ki1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kl_status, kl_token, mcuxClKey_loadCopro(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ kwk,
    /* uint32_t loadOptions:               */ MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_6)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != kl_token) || (MCUXCLKEY_STATUS_OK != kl_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Key Init                                                               */
  /**************************************************************************/

  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki2_status, ki2_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ key,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData:                   */ wrappedKeyData,
    /* uint32_t keyDataLength:               */ sizeof(wrappedKeyData))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki2_token) || (MCUXCLKEY_STATUS_OK != ki2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* As the key data contains an already wrapped key, set the key handle's encoding accordingly. */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kse_status, kse_token, mcuxClKey_setEncoding(
    /* mcuxClSession_Handle_t session:     */ session,
    /* mcuxClKey_Handle_t key:             */ key,
    /* mcuxClKey_Encoding_t encoding:      */ mcuxClAes_Encoding_Rfc3394,
    /* const uint8_t * pAuxData:          */ (uint8_t*) kwkDesc,
    /* uint32_t auxDataLength:            */ sizeof(kwkDesc))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_setEncoding) != kse_token) || (MCUXCLKEY_STATUS_OK != kse_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /***************************************************************************/
  /* Because the key in use is not preloaded, the Clib will internally load  */
  /* the key to the SGI for every stage of the Multipart operation.          */
  /*                                                                         */
  /* Due to the key's RFC3394 encoding, the slot the key will be loaded to   */
  /* is fixed by HW to MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP.              */
   /**************************************************************************/

  /**************************************************************************/
  /* Encryption                                                             */
  /**************************************************************************/

  uint32_t outLength = 0U;
  uint32_t encryptedSize = 0U;
  uint8_t encryptedData[sizeof(encryptedRef)];

  /* Create a buffer for the context */
  uint32_t ctxBuf[MCUXCLCIPHER_AES_CONTEXT_SIZE_IN_WORDS];
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

  MCUXCLBUFFER_UPDATE(plainBuf, sizeof(plain)/2u);
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

  MCUXCLBUFFER_UPDATE(encryptedDataBuf, encryptedSize / 3u);
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
  /* Flush the loaded key                                                   */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf1_status, kf1_token, mcuxClKey_flush(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ kwk)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != kf1_token) || (MCUXCLKEY_STATUS_OK != kf1_status))
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
