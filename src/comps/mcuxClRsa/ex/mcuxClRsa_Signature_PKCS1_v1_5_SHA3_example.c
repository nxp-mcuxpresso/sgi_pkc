/*--------------------------------------------------------------------------*/
/* Copyright 2024-2026 NXP                                                  */
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
 * @example mcuxClRsa_Signature_PKCS1_v1_5_SHA3_example.c
 * @brief mcuxClRsa example application
 */

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClRsa.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClSignature.h>
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
#define INPUT_MESSAGE_LENGTH       (16U)                     ///< Arbitrary size of the message to be signed

/**
 * @brief Example value for public RSA modulus N.
 */
static const uint8_t modulus[RSA_KEY_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0xe2U, 0x0eU, 0x89U, 0x3fU, 0xf1U, 0x75U, 0x9eU, 0x13U, 0x8cU, 0x58U, 0xe3U, 0xf8U, 0x20U, 0x00U, 0x94U, 0x99U,
  0x9bU, 0x43U, 0x4fU, 0xceU, 0x73U, 0x53U, 0x54U, 0xa9U, 0x7bU, 0x81U, 0xe9U, 0x35U, 0x18U, 0x2cU, 0xe5U, 0x0eU,
  0xd1U, 0x9bU, 0xf9U, 0x52U, 0xc6U, 0x67U, 0xb5U, 0xe1U, 0x5eU, 0x52U, 0xd8U, 0xa5U, 0xd3U, 0xecU, 0xb2U, 0x76U,
  0xd4U, 0xe7U, 0xffU, 0x7cU, 0x7cU, 0x7aU, 0xcbU, 0x6bU, 0x16U, 0x49U, 0x72U, 0x09U, 0xb3U, 0xc4U, 0x47U, 0x46U,
  0xd8U, 0xb2U, 0x65U, 0xdcU, 0x79U, 0x81U, 0x04U, 0xa7U, 0x90U, 0x0fU, 0xe2U, 0xd8U, 0xe0U, 0xb0U, 0x97U, 0xe5U,
  0x33U, 0xddU, 0x24U, 0xedU, 0x67U, 0xbfU, 0xe5U, 0x92U, 0x16U, 0x18U, 0x0bU, 0x17U, 0x95U, 0x2fU, 0xc6U, 0x34U,
  0x7bU, 0x35U, 0x76U, 0xa9U, 0x33U, 0x7eU, 0xf0U, 0xdeU, 0x2cU, 0xf0U, 0xd4U, 0x7aU, 0x38U, 0x3fU, 0x63U, 0xc7U,
  0xb2U, 0x48U, 0x8dU, 0x74U, 0x5aU, 0x8aU, 0x15U, 0x50U, 0x26U, 0x72U, 0x74U, 0xe3U, 0x45U, 0x4bU, 0xbaU, 0x4aU,
  0x6bU, 0xecU, 0x57U, 0x8fU, 0xdaU, 0x0aU, 0x04U, 0x90U, 0x89U, 0x2fU, 0x4aU, 0x7eU, 0x6bU, 0x3bU, 0x5aU, 0x37U,
  0xc2U, 0x39U, 0x08U, 0x2cU, 0x03U, 0xe5U, 0x86U, 0xc7U, 0xcaU, 0xceU, 0x9eU, 0xe1U, 0xcdU, 0x7cU, 0x2cU, 0xc9U,
  0xecU, 0x7cU, 0x11U, 0x72U, 0xddU, 0xa7U, 0x86U, 0x7aU, 0xcfU, 0xe8U, 0x06U, 0x1fU, 0x01U, 0x23U, 0xe2U, 0x56U,
  0xcdU, 0x68U, 0x71U, 0x32U, 0x2fU, 0xb8U, 0xb0U, 0x36U, 0x83U, 0xa3U, 0x58U, 0x91U, 0xe8U, 0x99U, 0x14U, 0x2aU,
  0xf7U, 0x18U, 0xcdU, 0xb8U, 0x8dU, 0x47U, 0x53U, 0x61U, 0x52U, 0xf5U, 0xd7U, 0xfaU, 0x2aU, 0x3cU, 0xc4U, 0x8bU,
  0x21U, 0x0cU, 0xbaU, 0x16U, 0x8bU, 0xfcU, 0xb8U, 0xd9U, 0xe8U, 0xd2U, 0x91U, 0x0dU, 0x53U, 0xe5U, 0xa8U, 0x11U,
  0xa7U, 0x58U, 0xa1U, 0x7aU, 0xe8U, 0xa3U, 0xf7U, 0xbeU, 0x3aU, 0x5fU, 0x73U, 0x02U, 0x09U, 0xb9U, 0x01U, 0xe9U,
  0xbeU, 0x6aU, 0xd7U, 0xc4U, 0x5fU, 0xecU, 0x7cU, 0xecU, 0x67U, 0xcbU, 0xeaU, 0x72U, 0x40U, 0xa4U, 0xe6U, 0xe5U
 };

/**
 * @brief Example value for private RSA exponent d.
 */
static const uint8_t privExp[RSA_KEY_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0x23U, 0x14U, 0x52U, 0x64U, 0x23U, 0xdaU, 0x36U, 0xafU, 0x9dU, 0xe5U, 0xe5U, 0x6aU, 0x89U, 0xbcU, 0xcdU, 0x52U,
  0x90U, 0xefU, 0x7fU, 0x20U, 0xf0U, 0x70U, 0x8cU, 0x00U, 0xc8U, 0xf3U, 0xbdU, 0xf6U, 0xc9U, 0x4bU, 0x9eU, 0x38U,
  0x10U, 0x7aU, 0xfdU, 0xd3U, 0xc4U, 0x8aU, 0x2fU, 0x85U, 0x4bU, 0x97U, 0xdbU, 0x9aU, 0xd0U, 0x2aU, 0x38U, 0xffU,
  0x8bU, 0xc6U, 0x7cU, 0xb5U, 0x1aU, 0xb4U, 0x0bU, 0x81U, 0x10U, 0xb2U, 0x51U, 0x0aU, 0x04U, 0x65U, 0x7fU, 0x12U,
  0x15U, 0x6aU, 0x89U, 0xb8U, 0x0eU, 0xfaU, 0xe0U, 0x78U, 0x08U, 0x39U, 0x0eU, 0xe0U, 0xccU, 0xedU, 0x5aU, 0x84U,
  0xecU, 0xe9U, 0x72U, 0x63U, 0x8cU, 0xe8U, 0x10U, 0x7dU, 0xfdU, 0x03U, 0xbaU, 0x24U, 0xecU, 0xb7U, 0xbfU, 0x30U,
  0x41U, 0xb6U, 0x68U, 0x35U, 0x95U, 0x92U, 0x2bU, 0x5aU, 0xaeU, 0xeaU, 0xa8U, 0x6eU, 0x56U, 0xf0U, 0x2fU, 0x51U,
  0xbbU, 0xeeU, 0xdaU, 0x54U, 0xa6U, 0x00U, 0x2bU, 0x92U, 0x86U, 0x84U, 0xd8U, 0x72U, 0xb4U, 0x3cU, 0x2eU, 0x2aU,
  0x37U, 0xa3U, 0x4cU, 0xf0U, 0xadU, 0xceU, 0x52U, 0xb0U, 0xb9U, 0x98U, 0xd4U, 0x9cU, 0xcdU, 0x04U, 0xc4U, 0x36U,
  0xa5U, 0x27U, 0xbeU, 0x2bU, 0x01U, 0x43U, 0x5cU, 0x21U, 0xedU, 0xd8U, 0x4bU, 0x62U, 0xecU, 0x58U, 0x76U, 0x53U,
  0xecU, 0x39U, 0x05U, 0x5cU, 0x2eU, 0xd0U, 0x4bU, 0x0aU, 0x4aU, 0x33U, 0x0fU, 0xeeU, 0xcdU, 0x7dU, 0x28U, 0xb6U,
  0xc3U, 0xf3U, 0xcfU, 0x91U, 0x3aU, 0xa5U, 0x7aU, 0x8dU, 0x06U, 0x71U, 0xd8U, 0x9fU, 0x21U, 0x40U, 0xb8U, 0x0eU,
  0x66U, 0xd2U, 0x1bU, 0x09U, 0xf9U, 0x7aU, 0x83U, 0x28U, 0x9eU, 0x2eU, 0x5aU, 0xd8U, 0x61U, 0xf6U, 0xccU, 0x28U,
  0x4fU, 0x8eU, 0xd7U, 0xfeU, 0xbcU, 0xb6U, 0x86U, 0x99U, 0x57U, 0xc4U, 0x10U, 0xbeU, 0x9cU, 0xbfU, 0xb5U, 0x93U,
  0xdcU, 0x33U, 0xdeU, 0x6dU, 0x7cU, 0x7bU, 0x50U, 0xe1U, 0x66U, 0xd9U, 0x5dU, 0x99U, 0xb0U, 0xe7U, 0x78U, 0x41U,
  0xa4U, 0xf4U, 0x72U, 0xc3U, 0x67U, 0x39U, 0xcfU, 0xd9U, 0xd9U, 0xd7U, 0x8dU, 0x66U, 0xe1U, 0x70U, 0x04U, 0xc1U
};

/**
 * @brief Example value for public RSA exponent e.
 */
static const uint8_t pubExp[RSA_PUBLIC_EXP_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0x01U, 0x00U, 0x01U
};

/**
 * @brief Example data to be signed.
 */
static const uint8_t data[INPUT_MESSAGE_LENGTH] = {
  0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U
};

/**
 * @brief Example expected signature.
 */
unsigned char signatureRef[] = {
  0x1aU, 0x7fU, 0xf2U, 0x6eU, 0xbaU, 0x9bU, 0xcbU, 0x72U, 0x5bU, 0xf1U, 0x1bU, 0xddU, 0x8bU, 0x91U, 0xfdU, 0x52U,
  0xbeU, 0x64U, 0x3eU, 0x45U, 0xf8U, 0xf9U, 0xebU, 0xdcU, 0xd6U, 0x2fU, 0xa3U, 0x31U, 0x8dU, 0x24U, 0xd0U, 0x6eU,
  0x6eU, 0x6bU, 0xd1U, 0x6cU, 0xc3U, 0xbaU, 0x58U, 0x0bU, 0x06U, 0x84U, 0x22U, 0xf5U, 0x47U, 0xabU, 0x8aU, 0x3eU,
  0xfdU, 0x0aU, 0xf3U, 0xbeU, 0x2cU, 0x09U, 0x03U, 0xceU, 0x63U, 0x43U, 0xdaU, 0x0bU, 0xa7U, 0x83U, 0xa9U, 0x8cU,
  0xc4U, 0x57U, 0x07U, 0x0cU, 0xb9U, 0xd5U, 0xe0U, 0xc2U, 0xfeU, 0xbaU, 0xc8U, 0x13U, 0x7bU, 0xd3U, 0x9cU, 0xc4U,
  0x2aU, 0xb2U, 0xe5U, 0x51U, 0x56U, 0xfbU, 0xc6U, 0x67U, 0xc6U, 0x07U, 0xe1U, 0x12U, 0x41U, 0x23U, 0xacU, 0x43U,
  0xefU, 0xbbU, 0x8bU, 0xe5U, 0x4fU, 0x3dU, 0x0fU, 0xe1U, 0x6bU, 0x18U, 0xa7U, 0x17U, 0x7bU, 0x2dU, 0x6fU, 0xcfU,
  0x93U, 0xa0U, 0x67U, 0xf0U, 0x54U, 0x63U, 0x8fU, 0xabU, 0xc9U, 0xbcU, 0x0eU, 0xa1U, 0xb9U, 0x77U, 0x93U, 0x78U,
  0x15U, 0x71U, 0x84U, 0x02U, 0x05U, 0x42U, 0x23U, 0xa2U, 0x5bU, 0xdaU, 0x5cU, 0x79U, 0x1aU, 0x81U, 0xbbU, 0x32U,
  0x71U, 0x07U, 0xc5U, 0x4cU, 0x91U, 0x7bU, 0xf2U, 0x94U, 0x56U, 0x66U, 0xd3U, 0x58U, 0x8aU, 0x69U, 0x97U, 0x30U,
  0xbcU, 0x7cU, 0x86U, 0xdbU, 0x7eU, 0xc0U, 0x3fU, 0xbcU, 0x7aU, 0x26U, 0x2fU, 0x76U, 0x8aU, 0xb9U, 0x47U, 0xafU,
  0x0bU, 0xe8U, 0x6bU, 0x6dU, 0xb9U, 0xd5U, 0xb0U, 0xd6U, 0x4dU, 0xfbU, 0x7eU, 0x14U, 0x8aU, 0x57U, 0x6fU, 0x51U,
  0x96U, 0x89U, 0x0cU, 0x2fU, 0x3eU, 0x62U, 0xefU, 0x31U, 0x73U, 0xccU, 0x11U, 0x72U, 0x7eU, 0xf7U, 0x06U, 0x28U,
  0xdfU, 0x2fU, 0x7fU, 0x19U, 0x67U, 0x96U, 0x45U, 0x42U, 0x24U, 0xbaU, 0xbeU, 0x73U, 0xbdU, 0x69U, 0x63U, 0x29U,
  0xc8U, 0xd4U, 0xd0U, 0xdcU, 0x8eU, 0x6fU, 0xbeU, 0x6eU, 0x63U, 0x85U, 0xfaU, 0x64U, 0xebU, 0x40U, 0x24U, 0x0fU,
  0x95U, 0xd4U, 0xbbU, 0x11U, 0x80U, 0x78U, 0x88U, 0x2bU, 0x77U, 0x68U, 0x4eU, 0x14U, 0x13U, 0x3bU, 0x7eU, 0x3cU
};

MCUXCLEXAMPLE_FUNCTION(mcuxClRsa_Signature_PKCS1_v1_5_SHA3_example)
{
  /**************************************************************************/
  /* Preparation: setup session                                             */
  /**************************************************************************/
  #define CPU_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLCORE_MAX(MCUXCLCORE_MAX(\
                                                MCUXCLRANDOM_NCINIT_WACPU_SIZE,\
                                                MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(RSA_KEY_BIT_LENGTH)),\
                                                MCUXCLRSA_VERIFY_PKCS1V15VERIFY_WACPU_SIZE),\
                                                MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_MAX)

  #define PKC_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLRSA_SIGN_PLAIN_WAPKC_SIZE(RSA_KEY_BIT_LENGTH),\
                                                MCUXCLRSA_VERIFY_WAPKC_SIZE(RSA_KEY_BIT_LENGTH))

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                              CPU_WA_BUFFER_SIZE,
                                              PKC_WA_BUFFER_SIZE);
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  /**************************************************************************/
  /* Preparation: setup RSA key                                             */
  /**************************************************************************/

  mcuxClRsa_KeyData_Plain_t privKeyStruct = {
                              .modulus.pKeyEntryData = (uint8_t*)modulus,
                              .modulus.keyEntryLength = RSA_KEY_BYTE_LENGTH,
                              .exponent.pKeyEntryData = (uint8_t*)privExp,
                              .exponent.keyEntryLength = sizeof(privExp)
  };

  mcuxClRsa_KeyData_Plain_t pubKeyStruct = {
                              .modulus.pKeyEntryData = (uint8_t*)modulus,
                              .modulus.keyEntryLength = RSA_KEY_BYTE_LENGTH,
                              .exponent.pKeyEntryData = (uint8_t*)pubExp,
                              .exponent.keyEntryLength = sizeof(pubExp)
  };

  /* Initialize RSA private key */
  uint8_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
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
  uint8_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
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
  /* Preparation: setup RSA PKCS1_v1_5 mode with SHA3-256                   */
  /**************************************************************************/

  /* Fill mode descriptor with the relevant data for the selected padding and hash algorithms */
  uint8_t signatureModeBytes[MCUXCLSIGNATURE_MODE_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClSignature_ModeDescriptor_t *pSignatureMode = (mcuxClSignature_ModeDescriptor_t *) signatureModeBytes;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  uint8_t rsaProtocolDescriptorBytes[MCUXCLRSA_SIGNATURE_PROTOCOLDESCRIPTOR_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClRsa_SignatureProtocolDescriptor_t *pRsaProtocolDescriptor = (mcuxClRsa_SignatureProtocolDescriptor_t *) rsaProtocolDescriptorBytes;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClHash_Algo_t pHashAlg = mcuxClHash_Algorithm_Sha3_256;

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(construct_mode_token,
    mcuxClRsa_SignatureModeConstructor_RSASSA_PKCS1_v1_5(
      /* mcuxClSignature_ModeDescriptor_t * pSignatureMode: */ pSignatureMode,
      /* mcuxClRsa_SignatureProtocolDescriptor_t * pProtocolDescriptor: */ pRsaProtocolDescriptor,
      /* mcuxClHash_Algo_t hashAlgorithm: */ pHashAlg,
      /* uint32_t options: */ 0u
    )
  );

  if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_SignatureModeConstructor_RSASSA_PKCS1_v1_5) != construct_mode_token)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

  /**************************************************************************/
  /* Hash computation                                                       */
  /**************************************************************************/

  uint8_t hash[MCUXCLHASH_OUTPUT_SIZE_SHA3_256];
  MCUXCLBUFFER_INIT(hashBuf, session, hash, MCUXCLHASH_OUTPUT_SIZE_SHA3_256);
  MCUXCLBUFFER_INIT_RO(dataBuf, session, data, INPUT_MESSAGE_LENGTH);
  uint32_t hashSize = 0;
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(hash_status, hash_token, mcuxClHash_compute(
    /* mcuxClSession_Handle_t session  */ session,
    /* mcuxClHash_Algo_t algorithm     */ pHashAlg,
    /* mcuxCl_InputBuffer_t pIn        */ dataBuf,
    /* uint32_t inSize                */ sizeof(data),
    /* mcuxCl_Buffer_t pOut            */ hashBuf,
    /* uint32_t * const pOutSize      */ &hashSize
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != hash_token) || (MCUXCLHASH_STATUS_OK != hash_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Signature generation                                                   */
  /**************************************************************************/

  uint8_t signature[RSA_KEY_BYTE_LENGTH];
  uint32_t signatureSize = 0;
  MCUXCLBUFFER_INIT(signatureBuf, session, signature, RSA_KEY_BYTE_LENGTH);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("hashBuf initialized by mcuxClHash_compute")
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ss_status, ss_token, mcuxClSignature_sign(
    /* mcuxClSession_Handle_t session:   */ session,
    /* mcuxClKey_Handle_t key:           */ privKey,
    /* mcuxClSignature_Mode_t mode:      */ pSignatureMode,
    /* mcuxCl_InputBuffer_t pIn:         */ (mcuxCl_InputBuffer_t)hashBuf,
    /* uint32_t inSize:                 */ sizeof(hash),
    /* mcuxCl_Buffer_t pSignature:       */ signatureBuf,
    /* uint32_t * const pSignatureSize: */ &signatureSize
  ));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != ss_token) || (MCUXCLSIGNATURE_STATUS_OK != ss_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(sizeof(signature) != signatureSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Compare the output signature with the expected data */
  if(!mcuxClCore_assertEqual(signature, signatureRef, signatureSize))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /**************************************************************************/
  /* Signature Verification                                                 */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sv_status, sv_token, mcuxClSignature_verify(
    /* mcuxClSession_Handle_t session:  */ session,
    /* mcuxClKey_Handle_t key:          */ pubKey,
    /* mcuxClSignature_Mode_t mode:     */ pSignatureMode,
    /* mcuxCl_InputBuffer_t pIn:        */ (mcuxCl_InputBuffer_t)hashBuf,
    /* uint32_t inSize:                */ sizeof(hash),
    /* mcuxCl_InputBuffer_t pSignature: */ (mcuxCl_InputBuffer_t)signatureBuf,
    /* uint32_t signatureSize:         */ signatureSize
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify) != sv_token) || (MCUXCLSIGNATURE_STATUS_OK != sv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Destroy the current session and exit                                   */
  /**************************************************************************/

  if(!mcuxClExample_Session_Clean(session))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
