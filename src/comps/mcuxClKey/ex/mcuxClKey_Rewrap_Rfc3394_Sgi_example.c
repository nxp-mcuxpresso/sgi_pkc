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
 * @example mcuxClKey_Rewrap_Rfc3394_Sgi_example.c
 * @brief   Example for the mcuxClKey component for RFC3394 key rewrap using
 *          the SGI coprocessor.
 */

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClAes.h> // Interface to AES-related definitions and types
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClBuffer.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

/** Test vectors are taken from https://datatracker.ietf.org/doc/html/rfc3394 */

/* Already wrapped key data. This is wrapped by the transport key. */
static const uint8_t wrappedKeyData[MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE] = {
  0x1FU, 0xA6U, 0x8BU, 0x0AU, 0x81U, 0x12U, 0xB4U, 0x47U,
  0xAEU, 0xF3U, 0x4BU, 0xD8U, 0xFBU, 0x5AU, 0x7BU, 0x82U,
  0x9DU, 0x3EU, 0x86U, 0x23U, 0x71U, 0xD2U, 0xCFU, 0xE5U
};

/* Transport key which performed the initial key wrap on the plain key material. */
static const uint8_t transportKeyData[MCUXCLAES_AES128_KEY_SIZE] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
  0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
};

/* Key-wrapping key (KWK) to rewrap the key material with. */
static const uint8_t kwk256Data[MCUXCLAES_AES256_KEY_SIZE] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
  0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
  0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
  0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
};

/* Expected rewrapped key data. */
static const uint8_t expectedRewrappedKeyData[MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE] = {
  0x64U, 0xE8U, 0xC3U, 0xF9U, 0xCEU, 0x0FU, 0x5BU, 0xA2U,
  0x63U, 0xE9U, 0x77U, 0x79U, 0x05U, 0x81U, 0x8AU, 0x2AU,
  0x93U, 0xC8U, 0x19U, 0x1EU, 0x7DU, 0x6EU, 0x8AU, 0xE7U
};

/**
 * @brief This examples showcases the RFC3394 rewrap using the SGI coprocessor.
 * The key data is assumed to be already wrapped by the transport key, and is
 * then unwrapped and rewrapped in a single step using the mcuxClKey_recode API.
 * Both key-wrapping keys (transport key and new KWK) are loaded into the SGI.
 * The new key is initialized and rewrapped using the mcuxClKey_recode API.
 * The resulting key handle will contain the rewrapped key material that can
 * be used for cryptographic operations.
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClKey_Rewrap_Rfc3394_Sgi_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_RECODE_CPU_WA_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0U);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);


  /**************************************************************************/
  /* Key Init and load the 128-bit transport key                            */
  /**************************************************************************/

  uint32_t transportKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t transportKey = (mcuxClKey_Handle_t) &transportKeyDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status, ki_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ transportKey,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData:                   */ (uint8_t *) transportKeyData,
    /* uint32_t keyDataLength:               */ sizeof(transportKeyData))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) || (MCUXCLKEY_STATUS_OK != ki_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kl_status, kl_token, mcuxClKey_loadCopro(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ transportKey,
    /* uint32_t loadOptions:               */ MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_2)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != kl_token) || (MCUXCLKEY_STATUS_OK != kl_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Key Init the already wrapped key                                       */
  /**************************************************************************/

  uint32_t wrappedKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t wrappedKey = (mcuxClKey_Handle_t) &wrappedKeyDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki2_status, ki2_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ wrappedKey,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData:                   */ (uint8_t *) wrappedKeyData,
    /* uint32_t keyDataLength:               */ sizeof(wrappedKeyData))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki2_token) || (MCUXCLKEY_STATUS_OK != ki2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**
   * As the key data contains an already wrapped key, set the key handle's encoding accordingly.
   * The auxiliary data shall be the key-wrapping-key key object.
   *
   * Attention: the transport key shall not be flushed until after the rewrap is done.
   */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kse_status, kse_token, mcuxClKey_setEncoding(
    /* mcuxClSession_Handle_t session:     */ session,
    /* mcuxClKey_Handle_t key:             */ wrappedKey,
    /* mcuxClKey_Encoding_t encoding:      */ mcuxClAes_Encoding_Rfc3394,
    /* const uint8_t * pAuxData:          */ (uint8_t*) transportKeyDesc,
    /* uint32_t auxDataLength:            */ sizeof(transportKeyDesc))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_setEncoding) != kse_token) || (MCUXCLKEY_STATUS_OK != kse_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Key Init and load the 256-bit rewrapping key                           */
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
  /* Key Rewrap using the mcuxClKey_recode API                               */
  /**************************************************************************/

  /**
   * Perform a rewrap of the wrapped key data. The key is unwrapped and then
   * rewrapped with the KWK in the given key slot.
   * The mcuxClKey_recode API takes care of properly initializing the new
   * key handle, no previous call to mcuxClKey_init is needed.
   *
   * The auxiliary data shall be the key-wrapping-key key object for the
   * new wrapping key (rewrapping key).
   */

  uint32_t reWrappedKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t reWrappedKey = (mcuxClKey_Handle_t) &reWrappedKeyDesc;
  uint8_t reWrappedKeyData[MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE];
  uint32_t reWrappedKeyLen = 0u;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kre_status, kre_token, mcuxClKey_recode(
    /* mcuxClSession_Handle_t session:            */ session,
    /* mcuxClKey_Handle_t encodedKey:             */ wrappedKey,
    /* mcuxClKey_Encoding_t encoding:             */ mcuxClAes_Encoding_Rfc3394,
    /* mcuxClKey_Handle_t recodedKey:             */ reWrappedKey,
    /* const uint8_t * pAuxData:                 */ (uint8_t*) keyWrappingKeyDesc,
    /* uint32_t auxDataLength:                   */ sizeof(keyWrappingKeyDesc),
    /* uint8_t * pEncodedKeyData:                */ reWrappedKeyData,
    /* uint32_t * const pEncodedKeyDataLength:   */ &reWrappedKeyLen)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_recode) != kre_token) || (MCUXCLKEY_STATUS_OK != kre_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Verification                                                           */
  /**************************************************************************/

  if(!mcuxClCore_assertEqual(reWrappedKeyData, expectedRewrappedKeyData, sizeof(expectedRewrappedKeyData)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE != reWrappedKeyLen)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }


  /**************************************************************************/
  /* Crypto Operation                                                       */
  /**************************************************************************/

  /**
   * The rewrapped key handle can now be used for cryptographic operations.
   *
   * Attention: The key is not preloaded into an SGI key slot yet. This needs
   * to be done manually using the mcuxClKey_loadCopro API. Without preloading,
   * each cryptographic operation will freshly load the key before usage
   * and flush it afterwards.
   * Note that due to SGI limitations for RFC3394 encoding, the slot that a
   * RFC3394-wrapped key can be loaded to is limited to
   * MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP.
   */


  /**************************************************************************/
  /* Flush the loaded keys                                                  */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf1_status, kf1_token, mcuxClKey_flush(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ transportKey)
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
