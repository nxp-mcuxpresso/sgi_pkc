/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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
 * @example mcuxClKey_Unwrap_Rfc3394_Sgi_example.c
 * @brief   Example for the mcuxClKey component for RFC3394 key unwrap/load
 *          into an SGI key slot.
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

/** Test vectors are taken from https://datatracker.ietf.org/doc/html/rfc3394 */
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
  0x6cU, 0x6dU, 0x6eU, 0x6fU, 0x70U, 0x71U, 0x72U, 0x73U,
};

/* CBC IV */
static const uint8_t iv[16] = {
  0x7aU, 0x79U, 0x78U, 0x77U, 0x76U, 0x75U, 0x74U, 0x73U,
  0x72U, 0x71U, 0x70U, 0x6fU, 0x6eU, 0x6dU, 0x6cU, 0x6bU
};

/* CBC encrypted data - plain data encrypted with the expected unwrapped key material.
 * Expected unwrapped key material: 00112233445566778899AABBCCDDEEFF */
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

/**
 * @brief This examples showcases the RFC3394 key unwrap using the SGI coprocessor,
 * which also loads the key material into an SGI key slot.
 * The key data is assumed to be already wrapped by a key-wrapping key (KWK)
 * that is already loaded in the SGI (e.g., this KWK was previously derived/defined
 * and then loaded to an SGI key slot).
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClKey_Unwrap_Rfc3394_Sgi_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_LOADCOPRO_CPU_WA_SIZE,
                                                          MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHER_AES_ENCRYPT_CPU_WA_BUFFER_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE)
                                                        ), 0U);
  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);


  /**************************************************************************/
  /* Key Init and "load" the key-wrapping key                               */
  /**************************************************************************/

  uint32_t keyWrappingKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t keyWrappingKey = (mcuxClKey_Handle_t) &keyWrappingKeyDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kiKwk_status, kiKwk_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ keyWrappingKey,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes256,
    /* uint8_t * pKeyData:                   */ (uint8_t *) kwk256Data,
    /* uint32_t keyDataLength:               */ sizeof(kwk256Data))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != kiKwk_token) || (MCUXCLKEY_STATUS_OK != kiKwk_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(klKwk_status, klKwk_token, mcuxClKey_loadCopro(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ keyWrappingKey,
    /* uint32_t loadOptions:               */ MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_6)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != klKwk_token) || (MCUXCLKEY_STATUS_OK != klKwk_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Key Init the wrapped key                                               */
  /**************************************************************************/

  uint32_t wrappedKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t wrappedKey = (mcuxClKey_Handle_t) &wrappedKeyDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status, ki_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ wrappedKey,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData:                   */ (uint8_t *) wrappedKeyData,
    /* uint32_t keyDataLength:               */ sizeof(wrappedKeyData))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) || (MCUXCLKEY_STATUS_OK != ki_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**
   * As the key data contains an already wrapped key, set the key handle's encoding accordingly.
   * The auxiliary data shall be the key-wrapping-key key object.
   */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kse_status, kse_token, mcuxClKey_setEncoding(
    /* mcuxClSession_Handle_t session:     */ session,
    /* mcuxClKey_Handle_t key:             */ wrappedKey,
    /* mcuxClKey_Encoding_t encoding:      */ mcuxClAes_Encoding_Rfc3394,
    /* const uint8_t * pAuxData:          */ (uint8_t*) keyWrappingKeyDesc,
    /* uint32_t auxDataLength:            */ sizeof(keyWrappingKeyDesc))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_setEncoding) != kse_token) || (MCUXCLKEY_STATUS_OK != kse_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Key Unwrap using the mcuxClKey_loadCopro API                            */
  /**************************************************************************/

  /**
   * This unwraps a key into the pre-defined SGI key slot, which is fixed
   * in HW, see MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP.
   */

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kl_status, kl_token, mcuxClKey_loadCopro(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ wrappedKey,
    /* uint32_t loadOptions:               */ MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != kl_token) || (MCUXCLKEY_STATUS_OK != kl_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Crypto Operation                                                       */
  /**************************************************************************/

  /**
   * The key handle can now be used for cryptographic operations.
   */


  /**************************************************************************/
  /* Encryption                                                             */
  /**************************************************************************/

  uint32_t encryptedSize = 0U;
  uint8_t encryptedData[sizeof(encryptedRef)];

  MCUXCLBUFFER_INIT_RO(plainBuf, session, plain, sizeof(plain));
  MCUXCLBUFFER_INIT_RO(ivBuf, session, iv, sizeof(iv));
  MCUXCLBUFFER_INIT(encryptedDataBuf, session, encryptedData, sizeof(encryptedData));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(e_status, e_token, mcuxClCipher_encrypt(
    /* mcuxClSession_Handle_t session:           */ session,
    /* const mcuxClKey_Handle_t key:             */ wrappedKey,
    /* mcuxClCipher_Mode_t mode:                 */ mcuxClCipher_Mode_AES_CBC_NoPadding,
    /* mcuxCl_InputBuffer_t pIv:                 */ ivBuf,
    /* uint32_t ivLength:                       */ sizeof(iv),
    /* mcuxCl_InputBuffer_t pIn:                 */ plainBuf,
    /* uint32_t inLength:                       */ sizeof(plain),
    /* mcuxCl_Buffer_t pOut:                     */ encryptedDataBuf,
    /* uint32_t * const outLength:              */ &encryptedSize) /* only relevant in case of padding being used */
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_encrypt) != e_token) || (MCUXCLCIPHER_STATUS_OK != e_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Verification                                                           */
  /**************************************************************************/

  if(encryptedSize != sizeof(encryptedRef))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(!mcuxClCore_assertEqual(encryptedRef, encryptedData, sizeof(encryptedRef)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }


  /**************************************************************************/
  /* Flush the loaded keys                                                  */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf1_status, kf1_token, mcuxClKey_flush(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ wrappedKey)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != kf1_token) || (MCUXCLKEY_STATUS_OK != kf1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf2_status, kf2_token, mcuxClKey_flush(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ keyWrappingKey)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != kf2_token) || (MCUXCLKEY_STATUS_OK != kf2_status))
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

  return MCUXCLEXAMPLE_STATUS_OK;
}
