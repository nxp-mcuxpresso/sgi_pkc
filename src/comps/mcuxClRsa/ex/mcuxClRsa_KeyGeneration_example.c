/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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
#define RSA_KEY_BYTE_LENGTH        (RSA_KEY_BIT_LENGTH / 8u) ///< Converting the key-bitlength to bytelength
#define RSA_PUBLIC_EXP_BYTE_LENGTH (3u)                      ///< The public exponent has a length of three bytes

/**
 * @brief Example value for public RSA exponent e.
 */
static const uint8_t pubExp[RSA_PUBLIC_EXP_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0x01u, 0x00u, 0x01u
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
  mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
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
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
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
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);

  /******************************************************************************/
  /* Preparation: setup RSA key generation mode                                 */
  /******************************************************************************/

  /* Fill mode descriptor with the relevant data for the RSA key generation */
  uint8_t keyGenModeBytes[MCUXCLRSA_KEYGEN_MODE_SIZE];
  mcuxClKey_GenerationDescriptor_t *pKeyGeneration_RSA_Mode = (mcuxClKey_GenerationDescriptor_t *) keyGenModeBytes;

  mcuxClRsa_KeyGeneration_ModeConstructor(
    /* mcuxClKey_GenerationDescriptor_t * pKeyGenMode: */ pKeyGeneration_RSA_Mode,
    /* const uint8_t * pE:                            */ pubExp,
    /* uint32_t eLength:                              */ sizeof(pubExp)
    );

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
