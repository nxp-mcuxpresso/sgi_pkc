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
 * @example mcuxClKey_WrapAndLoad_Rfc3394_Sgi_example.c
 * @brief   Example for the mcuxClKey component for RFC3394 key wrap and unwrap
 *          into an SGI key slot.
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


// Test vectors are taken from https://datatracker.ietf.org/doc/html/rfc3394
static const uint32_t keyData[MCUXCLAES_AES128_KEY_SIZE / 4U] = {
  0x33221100U, 0x77665544U, 0xBBAA9988U, 0xFFEEDDCCU
};

static const uint32_t kwk256Data[MCUXCLAES_AES256_KEY_SIZE / 4U] = {
  0x03020100U, 0x07060504U, 0x0B0A0908U, 0x0F0E0D0CU,
  0x13121110U, 0x17161514U, 0x1B1A1918U, 0x1F1E1D1CU
};

static const uint32_t expectedwrappedKeyData[MCUXCLAES_ENCODING_RFC3394_AES128_KEY_SIZE / 4U] = {
  0xF9C3E864U, 0xA25B0FCEU, 0x7977E963U, 0x2A8A8105U,
  0x1E19C893U, 0xE78A6E7DU
};


/**
 * @brief This examples showcases the RFC3394 key wrapping using the SGI coprocessor,
 * followed by RFC3394 key unwrapping, which preloads the key into an SGI key slot.
 * The key-wrapping key (KWK) for the key wrap is first loaded into the SGI.
 * Then, the main key is initialized and wrapped using the mcuxClKey_encode API.
 * The resulting key handle will contain the wrapped key material that can be used
 * for cryptographic operations. Then, the key is loaded into SGI using the
 * mcuxClKey_loadCopro API.
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClKey_WrapAndLoad_Rfc3394_Sgi_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
    MCUXCLEXAMPLE_MAX_WA(MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_ENCODE_CPU_WA_SIZE, MCUXCLKEY_LOADCOPRO_CPU_WA_SIZE), MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0U);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);


  /**************************************************************************/
  /* Key Init and load the key-wrapping key                                 */
  /**************************************************************************/

  uint32_t keyWrappingKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t keyWrappingKey = (mcuxClKey_Handle_t) &keyWrappingKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kiKwk_status, kiKwk_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ keyWrappingKey,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes256,
    /* uint8_t * pKeyData:                   */ (const uint8_t*)kwk256Data,
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
  /* Key Init+Wrap using the Key_encode API                                 */
  /**************************************************************************/

  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
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
    /* const uint8_t * pPlainKeyData:        */ (const uint8_t *)keyData,
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

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClKey_encode")
  if(!mcuxClCore_assertEqual(wrappedKeyData, (const uint8_t *)expectedwrappedKeyData, sizeof(expectedwrappedKeyData)))
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
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
   * to be done manually using the mcuxClKey_loadCopro API, see step below.
   * Without preloading, each cryptographic operation will freshly load the
   * key before usage and flush it afterwards.
   * Note that due to SGI limitations for RFC3394 encoding, the slot that a
   * RFC3394-wrapped key can be loaded to is limited to
   * MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP.
   *
   * See the next step for preloading the key.
   */


  /**************************************************************************/
  /* Key Load/Unwrap using the mcuxClKey_loadCopro API                       */
  /**************************************************************************/

  /**
   * This unwraps and loads a key into the predefined SGI key slot, which is fixed
   * in HW, see MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP.
   */

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kl_status, kl_token, mcuxClKey_loadCopro(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ key,
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
   * The key handle can now be used for cryptographic operations without
   * being freshly loaded each time.
   */


  /**************************************************************************/
  /* Flush the loaded keys                                                  */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kf1_status, kf1_token, mcuxClKey_flush(
    /* mcuxClSession_Handle_t session:      */ session,
    /* mcuxClKey_Handle_t key:              */ key)
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
