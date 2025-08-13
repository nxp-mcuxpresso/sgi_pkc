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
 * @example mcuxClKey_Load_Flush_Sgi_example.c
 * @brief   Example for the mcuxClKey component
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

/* CBC encrypted data */
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

static const uint8_t keyBytes[MCUXCLAES_AES128_KEY_SIZE] = {
  0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
  0x88U, 0x99U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU
};

MCUXCLEXAMPLE_FUNCTION(mcuxClKey_Load_Flush_Sgi_example)
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
  /* Key Init                                                               */
  /**************************************************************************/

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
  /* Key Load                                                               */
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
  /* Crypto Operation                                                       */
  /**************************************************************************/

  /**
   * The key handle can now be used for cryptographic operations without
   * being freshly loaded each time.
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
    /* const mcuxClKey_Handle_t key:             */ key,
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

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT")
  if(!mcuxClCore_assertEqual(encryptedRef, encryptedData, sizeof(encryptedRef)))
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }


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

  return MCUXCLEXAMPLE_STATUS_OK;
}
