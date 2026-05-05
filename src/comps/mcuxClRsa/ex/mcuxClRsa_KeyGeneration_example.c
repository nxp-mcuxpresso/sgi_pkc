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
 * @example mcuxClRsa_KeyGeneration_example.c
 * @brief   Example for the @ref mcuxCRsa component realize RSA key generation operation.
 */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClRsa.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>

/**********************************************************/
/* Example test vectors                                   */
/**********************************************************/
#define RSA_KEY_BIT_LENGTH         (MCUXCLKEY_SIZE_2048)      ///< The example uses a 2048-bit key
#define RSA_KEY_BYTE_LENGTH        (RSA_KEY_BIT_LENGTH / 8U) ///< Converting the key-bitlength to bytelength
#define RSA_PUBLIC_EXP_BYTE_LENGTH (3U)                      ///< The public exponent has a length of three bytes

/**
 * @brief Example value for public RSA exponent e.
 */
static const uint8_t pubExp[RSA_PUBLIC_EXP_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0x01U, 0x00U, 0x01U
};


MCUXCLEXAMPLE_FUNCTION(mcuxClRsa_KeyGeneration_example)
{
  /******************************************************************************/
  /* Preparation: setup session                                                 */
  /******************************************************************************/

#define CPU_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLCORE_MAX(\
                                              MCUXCLRANDOM_NCINIT_WACPU_SIZE,\
                                              MCUXCLRANDOMMODES_INIT_WACPU_SIZE),\
                                              MCUXCLRSA_KEYGENERATION_PLAIN_WACPU_SIZE(RSA_KEY_BIT_LENGTH))
#define PKC_WA_BUFFER_SIZE (MCUXCLRSA_KEYGENERATION_PLAIN_WAPKC_SIZE(RSA_KEY_BIT_LENGTH))


  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  //Allocate and initialize session
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                               CPU_WA_BUFFER_SIZE,
                                               PKC_WA_BUFFER_SIZE);

  /******************************************************************************/
  /* Preparation: setup RSA key                                                 */
  /******************************************************************************/

  /* Allocation of key data buffers, which contain RSA key parameters */

  /* Allocate space for and initialize RSA private key handle */
  uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  ALIGNED uint8_t pPrivKeyData[MCUXCLRSA_KEYGENERATION_PLAIN_KEY_DATA_2048_SIZE];

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_priv_status, ki_priv_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ privKey,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Rsa_PrivatePlain_2048,
    /* uint8_t * pKeyData                    */ pPrivKeyData,
    /* uint32_t keyDataLength                */ MCUXCLRSA_KEYGENERATION_PLAIN_KEY_DATA_2048_SIZE
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_priv_token) || (MCUXCLKEY_STATUS_OK != ki_priv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Allocate space for and initialize RSA public key handle */
  uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  ALIGNED uint8_t pPubKeyData[MCUXCLRSA_KEYGENERATION_PUBLIC_KEY_DATA_SIZE(RSA_KEY_BYTE_LENGTH, RSA_PUBLIC_EXP_BYTE_LENGTH)];

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_status, ki_pub_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ pubKey,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Rsa_Public_2048,
    /* uint8_t * pKeyData                    */ pPubKeyData,
    /* uint32_t keyDataLength                */ MCUXCLRSA_KEYGENERATION_PUBLIC_KEY_DATA_SIZE(RSA_KEY_BYTE_LENGTH, RSA_PUBLIC_EXP_BYTE_LENGTH)
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Initialize the RNG context and initialize the PRNG */
#if defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_256)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);
#elif defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_128)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES128_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES128_DRG3);
#else
  #error "Example not supported for target"
#endif

  /******************************************************************************/
  /* Preparation: setup RSA key generation mode                                 */
  /******************************************************************************/

  /* Fill mode descriptor with the relevant data for the RSA key generation */
  ALIGNED uint8_t keyGenModeBytes[MCUXCLRSA_KEYGEN_MODE_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_GenerationDescriptor_t *pKeyGeneration_RSA_Mode = (mcuxClKey_GenerationDescriptor_t *) keyGenModeBytes;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(construct_mode_token, mcuxClRsa_KeyGeneration_ModeConstructor(
    /* mcuxClKey_GenerationDescriptor_t * pKeyGenMode: */ pKeyGeneration_RSA_Mode,
    /* const uint8_t * pE:                            */ pubExp,
    /* uint32_t eLength:                              */ sizeof(pubExp)
    )
  );
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_KeyGeneration_ModeConstructor) != construct_mode_token)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

  /******************************************************************************/
  /* Key pair generation                                                        */
  /******************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(kgp_status, kgp_token, mcuxClKey_generate_keypair(
      /* mcuxClSession_Handle_t pSession:   */ session,
      /* mcuxClKey_Generation_t generation: */ pKeyGeneration_RSA_Mode,
      /* mcuxClKey_Handle_t privKey:        */ privKey,
      /* mcuxClKey_Handle_t pubKey:         */ pubKey
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_generate_keypair) != kgp_token) || (MCUXCLKEY_STATUS_OK != kgp_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();


  return MCUXCLEXAMPLE_STATUS_OK;
}
