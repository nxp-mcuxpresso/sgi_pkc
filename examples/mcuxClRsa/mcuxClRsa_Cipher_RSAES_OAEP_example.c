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
 * @example mcuxClRsa_Cipher_RSAES_OAEP_example.c
 * @brief mcuxClRsa example application
 */

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClRsa.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClCipher.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

/**********************************************************/
/* Example test vectors                                   */
/**********************************************************/

#define RSA_KEY_BIT_LENGTH         (MCUXCLKEY_SIZE_2048)      ///< The example uses a 2048-bit key
#define RSA_KEY_BYTE_LENGTH        (RSA_KEY_BIT_LENGTH / 8U) ///< Converting the key-bitlength to bytelength
#define RSA_PUBLIC_EXP_BYTE_LENGTH (3U)                      ///< The public exponent has a length of three bytes
#define RSA_OAEP_LABEL_LENGTH      (0U)                      ///< The label length is set to 0 in this example
#define INPUT_MESSAGE_LENGTH       (64U)                     ///< Arbitrary size of the message to be encrypted/decrypted

/**
 * @brief Example value for public RSA modulus N.
 */
static const uint8_t modulus[RSA_KEY_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0xd3U, 0x24U, 0x96U, 0xe6U, 0x2dU, 0x16U, 0x34U, 0x6eU, 0x06U, 0xe7U, 0xa3U, 0x1cU, 0x12U, 0x0aU, 0x21U, 0xb5U,
  0x45U, 0x32U, 0x32U, 0x35U, 0xeeU, 0x1dU, 0x90U, 0x72U, 0x1dU, 0xceU, 0xaaU, 0xd4U, 0x6dU, 0xc4U, 0xceU, 0xbdU,
  0x80U, 0xc1U, 0x34U, 0x5aU, 0xffU, 0x95U, 0xb1U, 0xddU, 0xf8U, 0x71U, 0xebU, 0xb7U, 0xf2U, 0x0fU, 0xedU, 0xb6U,
  0xe4U, 0x2eU, 0x67U, 0xa0U, 0xccU, 0x59U, 0xb3U, 0x9fU, 0xfdU, 0x31U, 0xe9U, 0x83U, 0x42U, 0xf4U, 0x0aU, 0xd9U,
  0xafU, 0xf9U, 0x3cU, 0x3cU, 0x51U, 0xcfU, 0x5fU, 0x3cU, 0x8aU, 0xd0U, 0x64U, 0xb8U, 0x33U, 0xf9U, 0xacU, 0x34U,
  0x22U, 0x9aU, 0x3eU, 0xd3U, 0xddU, 0x29U, 0x41U, 0xbeU, 0x12U, 0x5bU, 0xc5U, 0xa2U, 0x0cU, 0xb6U, 0xd2U, 0x31U,
  0xb6U, 0xd1U, 0x84U, 0x7eU, 0xc4U, 0xfeU, 0xaeU, 0x2bU, 0x88U, 0x46U, 0xcfU, 0x00U, 0xc4U, 0xc6U, 0xe7U, 0x5aU,
  0x51U, 0x32U, 0x65U, 0x7aU, 0x68U, 0xecU, 0x04U, 0x38U, 0x36U, 0x46U, 0x34U, 0xeaU, 0xf8U, 0x27U, 0xf9U, 0xbbU,
  0x51U, 0x6cU, 0x93U, 0x27U, 0x48U, 0x1dU, 0x58U, 0xb8U, 0xffU, 0x1eU, 0xa4U, 0xc0U, 0x1fU, 0xa1U, 0xa2U, 0x57U,
  0xa9U, 0x4eU, 0xa6U, 0xd4U, 0x72U, 0x60U, 0x3bU, 0x3fU, 0xb3U, 0x24U, 0x53U, 0x22U, 0x88U, 0xeaU, 0x3aU, 0x97U,
  0x43U, 0x53U, 0x59U, 0x15U, 0x33U, 0xa0U, 0xebU, 0xbeU, 0xf2U, 0x9dU, 0xf4U, 0xf8U, 0xbcU, 0x4dU, 0xdbU, 0xf8U,
  0x8eU, 0x47U, 0x1fU, 0x1dU, 0xa5U, 0x00U, 0xb8U, 0xf5U, 0x7bU, 0xb8U, 0xc3U, 0x7cU, 0xa5U, 0xeaU, 0x17U, 0x7cU,
  0x4eU, 0x8aU, 0x39U, 0x06U, 0xb7U, 0xc1U, 0x42U, 0xf7U, 0x78U, 0x8cU, 0x45U, 0xeaU, 0xd0U, 0xc9U, 0xbcU, 0x36U,
  0x92U, 0x48U, 0x3aU, 0xd8U, 0x13U, 0x61U, 0x11U, 0x45U, 0xb4U, 0x1fU, 0x9cU, 0x01U, 0x2eU, 0xf2U, 0x87U, 0xbeU,
  0x8bU, 0xbfU, 0x93U, 0x19U, 0xcfU, 0x4bU, 0x91U, 0x84U, 0xdcU, 0x8eU, 0xffU, 0x83U, 0x58U, 0x9bU, 0xe9U, 0x0cU,
  0x54U, 0x81U, 0x14U, 0xacU, 0xfaU, 0x5aU, 0xbfU, 0x79U, 0x54U, 0xbfU, 0x9fU, 0x7aU, 0xe5U, 0xb4U, 0x38U, 0xb5U
 };

/**
 * @brief Example value for private RSA exponent d.
 */
static const uint8_t privExp[RSA_KEY_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0x15U, 0x5fU, 0xe6U, 0x60U, 0xcdU, 0xdeU, 0xaaU, 0x17U, 0x1bU, 0x5eU, 0xd6U, 0xbdU, 0xd0U, 0x3bU, 0xb3U, 0x56U,
  0xe0U, 0xf6U, 0xe8U, 0x6bU, 0x5aU, 0x3cU, 0x26U, 0xf3U, 0xceU, 0x7dU, 0xaeU, 0x00U, 0x8cU, 0x4eU, 0x38U, 0xa9U,
  0xa9U, 0x7fU, 0xa5U, 0x97U, 0xb2U, 0xb9U, 0x0aU, 0x45U, 0x10U, 0xd2U, 0x23U, 0x8dU, 0x3fU, 0x15U, 0x8aU, 0xb8U,
  0x91U, 0x97U, 0xfbU, 0x08U, 0xa5U, 0xb7U, 0x4cU, 0xfeU, 0x5cU, 0xc8U, 0xf1U, 0x3dU, 0x47U, 0x09U, 0x62U, 0x91U,
  0xd0U, 0x05U, 0x38U, 0xaaU, 0x58U, 0x93U, 0xd8U, 0x2dU, 0xceU, 0x55U, 0xb3U, 0x64U, 0x8cU, 0x6aU, 0x71U, 0x9aU,
  0xe3U, 0x87U, 0xdeU, 0xe5U, 0x5eU, 0xc5U, 0xbeU, 0xf0U, 0x89U, 0x76U, 0x3dU, 0xe7U, 0x1eU, 0x47U, 0x61U, 0xb7U,
  0x03U, 0xadU, 0x69U, 0x2eU, 0xd6U, 0x2dU, 0x7cU, 0x1fU, 0x4fU, 0x0fU, 0xf0U, 0x03U, 0xc1U, 0x67U, 0xebU, 0x62U,
  0xd2U, 0xc6U, 0x79U, 0xccU, 0x6fU, 0x13U, 0xb9U, 0x87U, 0xa1U, 0x42U, 0xf1U, 0x37U, 0x7aU, 0x40U, 0xbdU, 0xc0U,
  0xa0U, 0x36U, 0x60U, 0x72U, 0x94U, 0x40U, 0x14U, 0x63U, 0xa3U, 0x0eU, 0x82U, 0x91U, 0x2bU, 0x42U, 0x8aU, 0x1dU,
  0x3fU, 0x80U, 0xb5U, 0xd0U, 0xd3U, 0x3eU, 0xa8U, 0x4eU, 0x8bU, 0xb6U, 0x4cU, 0x36U, 0x22U, 0xb9U, 0xbeU, 0xe3U,
  0x56U, 0xf1U, 0x2cU, 0x6aU, 0x19U, 0x0eU, 0x55U, 0x7bU, 0xbfU, 0x25U, 0xe1U, 0x10U, 0x80U, 0x7bU, 0x85U, 0xcaU,
  0xd5U, 0x1bU, 0x39U, 0x87U, 0x57U, 0x08U, 0x06U, 0xbeU, 0x81U, 0xf3U, 0x71U, 0x3fU, 0x5dU, 0x17U, 0x40U, 0x74U,
  0x99U, 0xa5U, 0xdeU, 0xdaU, 0xc0U, 0xf3U, 0xe3U, 0xbcU, 0x79U, 0x96U, 0x35U, 0x95U, 0xf8U, 0xe0U, 0xcfU, 0x01U,
  0x29U, 0x1dU, 0xc1U, 0x02U, 0x09U, 0xc0U, 0x6eU, 0xb6U, 0x0eU, 0x2eU, 0x9cU, 0x47U, 0xecU, 0x91U, 0x42U, 0xedU,
  0xa5U, 0xf3U, 0xb7U, 0x0aU, 0xc6U, 0x7fU, 0x72U, 0xbfU, 0x52U, 0xb3U, 0x31U, 0x37U, 0xd1U, 0x49U, 0xb6U, 0xf6U,
  0x06U, 0xe4U, 0x59U, 0x61U, 0x7dU, 0xaaU, 0x8eU, 0x10U, 0x18U, 0xa8U, 0x14U, 0x1dU, 0x89U, 0x4eU, 0xcaU, 0xffU
};

/**
 * @brief Example value for public RSA exponent e.
 */
static const uint8_t pubExp[RSA_PUBLIC_EXP_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0x01U, 0x00U, 0x01U
};

/**
 * @brief Example plaintext to be encrypted.
 */
static const uint8_t plainData[INPUT_MESSAGE_LENGTH] = {
  0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U,
  0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U,
  0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
  0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U, 0x73U
};


MCUXCLEXAMPLE_FUNCTION(mcuxClRsa_Cipher_RSAES_OAEP_example)
{
  /**************************************************************************/
  /* Preparation: setup session                                             */
  /**************************************************************************/

  #define CPU_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLCORE_MAX(MCUXCLCORE_MAX(\
                                              MCUXCLRANDOM_NCINIT_WACPU_SIZE,\
                                              MCUXCLRANDOMMODES_INIT_WACPU_SIZE),\
                                              MCUXCLRSA_ENCRYPT_WACPU_SIZE(RSA_KEY_BIT_LENGTH)),\
                                              MCUXCLRSA_DECRYPT_WACPU_SIZE(RSA_KEY_BIT_LENGTH))
  #define PKC_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLRSA_ENCRYPT_WAPKC_SIZE(RSA_KEY_BIT_LENGTH),\
                                              MCUXCLRSA_DECRYPT_WAPKC_SIZE(RSA_KEY_BIT_LENGTH))


  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  //Allocate and initialize session
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                              CPU_WA_BUFFER_SIZE,
                                              PKC_WA_BUFFER_SIZE);

  /**************************************************************************/
  /* Initialize the RNG context and initialize the PRNG                     */
  /**************************************************************************/

#if defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_128)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES128_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES128_DRG3);
#else
  #error "Example not supported for target"
#endif /* MCUXCL_FEATURE_RANDOMMODES_* */

  /**************************************************************************/
  /* Preparation: setup RSA key                                             */
  /**************************************************************************/

  /* Allocation of key data buffers, which contain RSA key parameters */
  mcuxClRsa_KeyData_Plain_t privKeyStruct  = {
                              .modulus.pKeyEntryData = (uint8_t*)modulus,
                              .modulus.keyEntryLength = RSA_KEY_BYTE_LENGTH,
                              .exponent.pKeyEntryData = (uint8_t*)privExp,
                              .exponent.keyEntryLength = sizeof(privExp)
  };

  mcuxClRsa_KeyData_Plain_t pubKeyStruct  = {
                              .modulus.pKeyEntryData = (uint8_t*)modulus,
                              .modulus.keyEntryLength = RSA_KEY_BYTE_LENGTH,
                              .exponent.pKeyEntryData = (uint8_t*)pubExp,
                              .exponent.keyEntryLength = sizeof(pubExp)
  };

  /* Initialize RSA private key */
  uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_priv_status, ki_priv_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ privKey,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Rsa_PrivatePlain_2048,
    /* uint8_t * pKeyData                    */ (uint8_t *) &privKeyStruct,
    /* uint32_t keyDataLength                */ sizeof(privKeyStruct)
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_priv_token) || (MCUXCLKEY_STATUS_OK != ki_priv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Initialize RSA public key */
  uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_status, ki_pub_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ pubKey,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Rsa_Public_2048,
    /* uint8_t * pKeyData                    */ (uint8_t *) &pubKeyStruct,
    /* uint32_t keyDataLength                */ sizeof(pubKeyStruct)
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Preparation: setup RSA OAEP mode with SHA-256                          */
  /**************************************************************************/

  /* Fill mode descriptor with the relevant data for the selected padding and hash algorithms */
  uint8_t cipherModeBytes[MCUXCLRSA_CIPHER_MODE_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClCipher_ModeDescriptor_t *pCipherMode = (mcuxClCipher_ModeDescriptor_t *) cipherModeBytes;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(construct_mode_token,
    mcuxClRsa_CipherModeConstructor_RSAES_OAEP(
      /* mcuxClCipher_ModeDescriptor_t * pCipherMode: */ pCipherMode,
      /* mcuxClHash_Algo_t hashAlgorithm: */ mcuxClHash_Algorithm_Sha256
    )
  );

  if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_CipherModeConstructor_RSAES_OAEP) != construct_mode_token)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

  /**************************************************************************/
  /* Encryption                                                             */
  /**************************************************************************/

  uint8_t encryptedData[RSA_KEY_BYTE_LENGTH];
  uint32_t encryptedSize = 0U;

  MCUXCLBUFFER_INIT_RO(plainDataBuf, session, plainData, INPUT_MESSAGE_LENGTH);
  MCUXCLBUFFER_INIT(encryptedDataBuf, session, encryptedData, RSA_KEY_BYTE_LENGTH);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("Pointer is not dereferenced")
  const mcuxClCipher_Status_t e_status = mcuxClCipher_encrypt(
    /* mcuxClSession_Handle_t session          */ session,
    /* const mcuxClKey_Handle_t key            */ pubKey,
    /* mcuxClCipher_Mode_t mode                */ pCipherMode,
    /* mcuxCl_InputBuffer_t pIv                */ NULL, /* label for OAEP decoding, set to NULL if no label is provided */
    /* uint32_t ivLength                      */ RSA_OAEP_LABEL_LENGTH, /* label length */
    /* mcuxCl_InputBuffer_t pIn                */ plainDataBuf,
    /* uint32_t inLength                      */ sizeof(plainData),
    /* mcuxCl_Buffer_t pOut                    */ encryptedDataBuf,
    /* uint32_t * const pOutLength            */ &encryptedSize
  );
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  if(MCUXCLCIPHER_STATUS_OK != e_status)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if(encryptedSize != sizeof(encryptedData))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /**************************************************************************/
  /* Decryption                                                             */
  /**************************************************************************/

  uint32_t decryptedSize = 0U;
  uint8_t decryptedData[INPUT_MESSAGE_LENGTH];
  MCUXCLBUFFER_INIT(decryptedDataBuf, session, decryptedData, INPUT_MESSAGE_LENGTH);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("Pointer pIv is not dereferenced")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("encryptedDataBuf initialized by MCUXCLBUFFER_INIT")
  const mcuxClCipher_Status_t d_status = mcuxClCipher_decrypt(
    /* mcuxClSession_Handle_t session         */ session,
    /* const mcuxClKey_Handle_t key           */ privKey,
    /* mcuxClCipher_Mode_t mode               */ pCipherMode,
    /* mcuxCl_InputBuffer_t pIv               */ NULL, /* label for OAEP decoding, set to NULL if no label is provided */
    /* uint32_t ivLength                     */ RSA_OAEP_LABEL_LENGTH, /* label length */
    /* mcuxCl_InputBuffer_t pIn               */ (mcuxCl_InputBuffer_t)encryptedDataBuf,
    /* uint32_t inLength                     */ encryptedSize,
    /* mcuxCl_Buffer_t pOut                   */ decryptedDataBuf,
    /* uint32_t * const pOutLength           */ &decryptedSize
  );
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  if(MCUXCLCIPHER_STATUS_OK != d_status)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if(decryptedSize != sizeof(decryptedData))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

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

  if(!mcuxClCore_assertEqual(plainData, decryptedData, sizeof(plainData)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
