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
 * @example mcuxClKey_Wrap_Rfc3394_Sgi_kwkAlreadyLoaded_example.c
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

/** Test vector is taken from https://datatracker.ietf.org/doc/html/rfc3394 */
static const uint8_t keyData[MCUXCLAES_AES128_KEY_SIZE] = {
  0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
  0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU
};

static const uint8_t kwk256Data[MCUXCLAES_AES256_KEY_SIZE] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
  0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
  0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
  0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU
};

static const uint8_t expectedwrappedKeyData[MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE] = {
  0x64U, 0xE8U, 0xC3U, 0xF9U, 0xCEU, 0x0FU, 0x5BU, 0xA2U,
  0x63U, 0xE9U, 0x77U, 0x79U, 0x05U, 0x81U, 0x8AU, 0x2AU,
  0x93U, 0xC8U, 0x19U, 0x1EU, 0x7DU, 0x6EU, 0x8AU, 0xE7U
};


/**
 * @brief This examples showcases the RFC3394 key wrap using the SGI coprocessor.
 * The key-wrapping key (KWK) for the key wrap is a KWK in the SGI, which is
 * assumed to be already loaded (e.g., this KWK was previously derived/defined
 * and then loaded to an SGI key slot).
 * The resulting key handle will contain the wrapped key material that can be used
 * for cryptographic operations.
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClKey_Wrap_Rfc3394_Sgi_kwkAlreadyLoaded_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_ENCODE_CPU_WA_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0U);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  /**************************************************************************/
  /* Load the Key data of the KWK to mimic that it is already loaded.       */
  /*                                                                        */
  /* !! ATTENTION !!                                                        */
  /*                                                                        */
  /* This step is only done to have some form of verification in this       */
  /* example for the end-result. It is never needed to call the             */
  /* mcuxClKey_loadCopro two times in a row (without a key flush in between) */
  /* in a real scenario.                                                    */
  /* The dummy key handle used here will be discarded after the load to SGI.*/
  /**************************************************************************/

  uint32_t dummyKwkDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t dummyKwk = (mcuxClKey_Handle_t) &dummyKwkDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kid_status, kid_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ dummyKwk,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes256,
    /* uint8_t * pKeyData:                   */ (uint8_t *) kwk256Data,
    /* uint32_t keyDataLength:               */ sizeof(kwk256Data))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != kid_token) || (MCUXCLKEY_STATUS_OK != kid_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Load the key data into SGI */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kld_status, kld_token, mcuxClKey_loadCopro(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ dummyKwk,
    /* uint32_t loadOptions:               */ MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_6)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != kld_token) || (MCUXCLKEY_STATUS_OK != kld_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**
   * This key handle, dummyKwk, is now "discarded", as it is not a real part
   * of this example flow.
   * The only purpose was to place the KWK data in the SGI.
   */



  /**************************************************************************/
  /* Key Init and "load" the key-wrapping key                               */
  /**************************************************************************/

  uint32_t keyWrappingKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t keyWrappingKey = (mcuxClKey_Handle_t) &keyWrappingKeyDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kiKwk_status, kiKwk_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ keyWrappingKey,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes256,
    /* uint8_t * pKeyData:                   */ (uint8_t *) NULL, /* not needed, key is already loaded */
    /* uint32_t keyDataLength:               */ 0u /* not needed, key is already loaded */)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != kiKwk_token) || (MCUXCLKEY_STATUS_OK != kiKwk_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**
   * Although the KWK data is already loaded into an SGI key slot,
   * call mcuxClKey_loadCopro to finish initialization of the key handle.
   * Use option MCUXCLKEY_LOADOPTION_ALREADYLOADED.
   *
   * For this example, the wrapping key is 256-bit and assumed in
   * MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_6.
   */

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(klKwk_status, klKwk_token, mcuxClKey_loadCopro(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ keyWrappingKey,
    /* uint32_t loadOptions:               */ MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_6
                                              | MCUXCLKEY_LOADOPTION_ALREADYLOADED)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != klKwk_token) || (MCUXCLKEY_STATUS_OK != klKwk_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Key Init+Wrap using the Key_encode API                                 */
  /**************************************************************************/

  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;
  uint8_t wrappedKeyData[MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE];
  uint32_t wrappedKeyLen = 0u;

  /**
   * The auxiliary data shall be the key-wrapping-key key object.
   */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ke_status, ke_token, mcuxClKey_encode(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Encoding_t encoding:         */ mcuxClAes_Encoding_Rfc3394,
    /* mcuxClKey_Handle_t encodedKey:         */ key,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes128,
    /* const uint8_t * pPlainKeyData:        */ (uint8_t *) keyData,
    /* uint32_t plainKeyDataLength:          */ sizeof(keyData),
    /* const uint8_t * pAuxData:             */ (uint8_t*) keyWrappingKeyDesc,
    /* uint32_t auxDataLength:               */ sizeof(keyWrappingKeyDesc),
    /* uint8_t * pEncodedKeyData:            */ wrappedKeyData,
    /* uint32_t* const pEncodedKeyDataLength:*/ &wrappedKeyLen)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_encode) != ke_token) || (MCUXCLKEY_STATUS_OK != ke_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Verification                                                           */
  /**************************************************************************/

  if(!mcuxClCore_assertEqual(wrappedKeyData, expectedwrappedKeyData, sizeof(expectedwrappedKeyData)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE != wrappedKeyLen)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }


  /**************************************************************************/
  /* Crypto Operation                                                       */
  /**************************************************************************/

  /**
   * The wrapped key handle can now be used for cryptographic operations.
   *
   * Attention: The key is not preloaded into an SGI key slot yet. This needs
   * to be done manually using the mcuxClKey_loadCopro API. Without preloading,
   * each cryptographic operation will freshly load the key before usage
   * and flush it afterwards.
   */


  /**************************************************************************/
  /* Flush the loaded keys                                                  */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf1_status, kf1_token, mcuxClKey_flush(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ dummyKwk)
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
