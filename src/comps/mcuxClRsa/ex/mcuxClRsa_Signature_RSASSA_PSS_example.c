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
 * @example mcuxClRsa_Signature_RSASSA_PSS_example.c
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
#include <mcuxClToolchain.h>

/**********************************************************/
/* Example test vectors                                   */
/**********************************************************/

#define RSA_KEY_BIT_LENGTH         (MCUXCLKEY_SIZE_2048)      ///< The example uses a 2048-bit key
#define RSA_KEY_BYTE_LENGTH        (RSA_KEY_BIT_LENGTH / 8U) ///< Converting the key-bitlength to bytelength
#define RSA_PUBLIC_EXP_BYTE_LENGTH (3U)                      ///< The public exponent has a length of three bytes
#define RSA_PSS_SALT_LENGTH        (0U)                      ///< The salt length is set to 0 in this example
#define INPUT_MESSAGE_LENGTH       (64U)                     ///< Arbitrary size of the message to be signed

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
 * @brief Example data to be signed.
 */
static const uint8_t data[INPUT_MESSAGE_LENGTH] = {
  0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U,
  0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U,
  0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
  0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U, 0x73U
};

MCUXCLEXAMPLE_FUNCTION(mcuxClRsa_Signature_RSASSA_PSS_example)
{
  /**************************************************************************/
  /* Preparation: setup session                                             */
  /**************************************************************************/
  #define CPU_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLCORE_MAX(MCUXCLCORE_MAX(MCUXCLCORE_MAX(\
                                              MCUXCLRANDOM_NCINIT_WACPU_SIZE,\
                                              MCUXCLRANDOMMODES_INIT_WACPU_SIZE),\
                                              MCUXCLRSA_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(RSA_KEY_BIT_LENGTH)),\
                                              MCUXCLRSA_VERIFY_PSSVERIFY_WACPU_SIZE),\
                                              MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_MAX)
  #define PKC_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLRSA_SIGN_PLAIN_WAPKC_SIZE(RSA_KEY_BIT_LENGTH),\
                                              MCUXCLRSA_VERIFY_WAPKC_SIZE(RSA_KEY_BIT_LENGTH))


  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  //Allocate and initialize session
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                              CPU_WA_BUFFER_SIZE,
                                              PKC_WA_BUFFER_SIZE);

  /**************************************************************************/
  /* Initialize the RNG context and initialize the PRNG                     */
  /**************************************************************************/

#if defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_256)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);
#elif defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_128)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES128_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES128_DRG3);
#else
  #error "Example not supported for target"
#endif

  /**************************************************************************/
  /* Preparation: setup RSA key                                             */
  /**************************************************************************/

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER()
  mcuxClRsa_KeyData_Plain_t privKeyStruct = {
                              .modulus.pKeyEntryData = (uint8_t*)modulus,
                              .modulus.keyEntryLength = RSA_KEY_BYTE_LENGTH,
                              .exponent.pKeyEntryData = (uint8_t*)privExp,
                              .exponent.keyEntryLength = sizeof(privExp)
  };
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER()
  mcuxClRsa_KeyData_Plain_t pubKeyStruct = {
                              .modulus.pKeyEntryData = (uint8_t*)modulus,
                              .modulus.keyEntryLength = RSA_KEY_BYTE_LENGTH,
                              .exponent.pKeyEntryData = (uint8_t*)pubExp,
                              .exponent.keyEntryLength = sizeof(pubExp)
  };
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()

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
  /* Preparation: setup RSA PSS mode with SHA-256                           */
  /**************************************************************************/

  /* Fill mode descriptor with the relevant data for the selected padding and hash algorithms */
  // TODO CLNS-9057: define one buffer size which covers both the mode & protocol descriptor, and remove the protocol descriptor parameter here
  ALIGNED uint8_t signatureModeBytes[MCUXCLSIGNATURE_MODE_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClSignature_ModeDescriptor_t *pSignatureMode = (mcuxClSignature_ModeDescriptor_t *) signatureModeBytes;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  ALIGNED uint8_t rsaProtocolDescriptorBytes[MCUXCLRSA_SIGNATURE_PROTOCOLDESCRIPTOR_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClRsa_SignatureProtocolDescriptor_t *pRsaProtocolDescriptor = (mcuxClRsa_SignatureProtocolDescriptor_t *) rsaProtocolDescriptorBytes;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(construct_mode_token,
    mcuxClRsa_SignatureModeConstructor_RSASSA_PSS(
      /* mcuxClSignature_ModeDescriptor_t * pSignatureMode: */ pSignatureMode,
      /* mcuxClRsa_SignatureProtocolDescriptor_t * pProtocolDescriptor: */ pRsaProtocolDescriptor,
      /* mcuxClHash_Algo_t hashAlgorithm: */ mcuxClHash_Algorithm_Sha256,
      /* uint32_t saltLength: */ RSA_PSS_SALT_LENGTH,
      /* uint32_t options: */ 0u
    )
  );
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_SignatureModeConstructor_RSASSA_PSS) != construct_mode_token)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

  /**************************************************************************/
  /* Hash computation                                                       */
  /**************************************************************************/

  uint8_t hash[MCUXCLHASH_OUTPUT_SIZE_SHA_256];
  MCUXCLBUFFER_INIT(hashBuf, session, hash, MCUXCLHASH_OUTPUT_SIZE_SHA_256);
  MCUXCLBUFFER_INIT_RO(dataBuf, session, data, INPUT_MESSAGE_LENGTH);
  uint32_t hashSize = 0;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(hash_status, hash_token, mcuxClHash_compute(
    /* mcuxClSession_Handle_t session  */ session,
    /* mcuxClHash_Algo_t algorithm     */ mcuxClHash_Algorithm_Sha256,
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

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ss_status, ss_token, mcuxClSignature_sign(
    /* mcuxClSession_Handle_t session:   */ session,
    /* mcuxClKey_Handle_t key:           */ privKey,
    /* mcuxClSignature_Mode_t mode:      */ pSignatureMode,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("hashBuf initialized by mcuxClHash_compute")
    /* mcuxCl_InputBuffer_t pIn:         */ (mcuxCl_InputBuffer_t)hashBuf,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* uint32_t inSize:                 */ sizeof(hash),
    /* mcuxCl_Buffer_t pSignature:       */ signatureBuf,
    /* uint32_t * const pSignatureSize: */ &signatureSize
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != ss_token) || (MCUXCLSIGNATURE_STATUS_OK != ss_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  if(signatureSize != sizeof(signature))
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
