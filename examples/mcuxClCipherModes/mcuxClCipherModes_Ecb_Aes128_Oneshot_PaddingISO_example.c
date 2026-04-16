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
 * @example mcuxClCipherModes_Ecb_Aes128_Oneshot_PaddingISO_example.c
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

MCUXCLEXAMPLE_FUNCTION(mcuxClCipherModes_Ecb_Aes128_Oneshot_PaddingISO_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

#define MCUXCLCIPHERMODES_CPU_WA MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHER_AES_ENCRYPT_CPU_WA_BUFFER_SIZE, MCUXCLCIPHER_AES_DECRYPT_CPU_WA_BUFFER_SIZE)


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

  uint32_t encryptedSize = 0U;
  uint8_t encryptedData[sizeof(encryptedRef)];

  MCUXCLBUFFER_INIT_RO(plainBuf, session, plain, sizeof(plain));
  MCUXCLBUFFER_INIT(encryptedDataBuf, session, encryptedData, sizeof(encryptedData));
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("Pointer is not dereferenced")
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(e_status, e_token, mcuxClCipher_encrypt(
    /* mcuxClSession_Handle_t session:           */ session,
    /* const mcuxClKey_Handle_t key:             */ key,
    /* mcuxClCipher_Mode_t mode:                 */ mcuxClCipher_Mode_AES_ECB_PaddingISO9797_1_Method2,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* mcuxCl_InputBuffer_t pIv:                 */ NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    /* uint32_t ivLength:                       */ 0,
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
    /* mcuxClCipher_Mode_t mode:                 */ mcuxClCipher_Mode_AES_ECB_PaddingISO9797_1_Method2,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* mcuxCl_InputBuffer_t pIv:                 */ NULL,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
    /* uint32_t ivLength:                       */ 0,
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
