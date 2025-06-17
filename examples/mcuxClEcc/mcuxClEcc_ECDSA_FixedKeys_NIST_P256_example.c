/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @example mcuxClEcc_ECDSA_FixedKeys_NIST_P256_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClKey.h>
#include <mcuxClHash.h>
#include <mcuxClSignature.h>
#include <mcuxClEcc.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>

static const uint8_t digest[] = {
  0xC4u, 0x93u, 0xCFu, 0x6Bu, 0xE5u, 0x11u, 0x35u, 0x22u,
  0x1Au, 0x3Fu, 0x5Cu, 0x7Bu, 0xCFu, 0xF4u, 0x6Du, 0xC6u,
  0x10u, 0x77u, 0x6Eu, 0x2Cu, 0x04u, 0xA3u, 0xB9u, 0x9Du,
  0x39u, 0x3Bu, 0x4Bu, 0xEEu, 0xD5u, 0xDDu, 0x88u, 0x86u,
};

static const ALIGNED uint8_t pPrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY] = {
  0x5Du, 0x37u, 0x8Du, 0xFDu, 0x5Cu, 0xDDu, 0x7Au, 0x37u,
  0xE7u, 0x0Fu, 0x1Au, 0xF7u, 0xFEu, 0x99u, 0xA5u, 0x16u,
  0xD4u, 0xE0u, 0xC4u, 0x34u, 0xD8u, 0x49u, 0x85u, 0xFBu,
  0x12u, 0x50u, 0x32u, 0x06u, 0x73u, 0x9Au, 0x96u, 0xF4u,
};

static const ALIGNED uint8_t pPubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {
  0x0Cu, 0xB2u, 0x52u, 0x2Fu, 0x18u, 0xF9u, 0xB5u, 0xA3u,
  0xADu, 0x3Au, 0xE0u, 0x99u, 0x75u, 0x5Au, 0x49u, 0xCDu,
  0xCEu, 0x4Bu, 0x05u, 0x14u, 0xB5u, 0xC6u, 0x15u, 0x07u,
  0xF0u, 0xC6u, 0x39u, 0xE7u, 0x1Au, 0xB4u, 0x4Cu, 0xDEu,
  0x68u, 0xF8u, 0xDFu, 0x58u, 0xA9u, 0xC0u, 0xF8u, 0x62u,
  0x35u, 0x9Cu, 0xB2u, 0x36u, 0xF9u, 0x29u, 0xABu, 0x9Fu,
  0x89u, 0xB1u, 0xA7u, 0xA2u, 0x34u, 0xC1u, 0xE4u, 0x57u,
  0x23u, 0xC7u, 0xE9u, 0x41u, 0x25u, 0x80u, 0x46u, 0xBBu,
};

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOM_NCINIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLSIGNATURE_SIGN_ECDSA_WACPU_SIZE, \
                    		         MCUXCLSIGNATURE_VERIFY_ECDSA_WACPU_SIZE)))

#define MAX_PKCWA_SIZE MCUXCLCORE_MAX(MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_256, \
                                     MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_256)

MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ECDSA_FixedKeys_NIST_P256_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /* Setup one session to be used by all functions called */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);


  /* Allocate space for and initialize private key handle for an ECDSA NIST P-256 private key */
  uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_priv_status, ki_priv_token, mcuxClKey_init(
   /* mcuxClSession_Handle_t session         */ session,
   /* mcuxClKey_Handle_t key                 */ privKey,
   /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Priv,
   /* const uint8_t * pKeyData              */ pPrivKeyData,
   /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_priv_token) || (MCUXCLKEY_STATUS_OK != ki_priv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Allocate space for and initialize private key handle for an ECDSA NIST P-256 public key */
  uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_status, ki_pub_token, mcuxClKey_init(
   /* mcuxClSession_Handle_t session         */ session,
   /* mcuxClKey_Handle_t key                 */ pubKey,
   /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Pub,
   /* const uint8_t * pKeyData              */ pPubKeyData,
   /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Initialize the RNG context and Initialize the PRNG */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);


  /**************************************************************************/
  /* ECDSA signature generation on NIST P-256                               */
  /**************************************************************************/

  uint8_t signature[MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE];
  MCUXCLBUFFER_INIT(buffSignature, NULL, signature, sizeof(MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE));
  uint32_t signatureSize = 0u;
  MCUXCLBUFFER_INIT_RO(buffDigest, NULL, digest, sizeof(digest));

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ss_status, ss_token, mcuxClSignature_sign(
    /* mcuxClSession_Handle_t session:   */ session,
    /* mcuxClKey_Handle_t key:           */ privKey,
    /* mcuxClSignature_Mode_t mode:      */ mcuxClSignature_Mode_ECDSA,
    /* mcuxCl_InputBuffer_t pIn:         */ buffDigest,
    /* uint32_t inSize:                 */ sizeof(digest),
    /* mcuxCl_Buffer_t pSignature:       */ buffSignature,
    /* uint32_t * const pSignatureSize: */ &signatureSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != ss_token) || (MCUXCLSIGNATURE_STATUS_OK != ss_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  if(MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE != signatureSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }


  /**************************************************************************/
  /* ECDSA signature verification on NIST P-256                             */
  /**************************************************************************/
  MCUXCLBUFFER_INIT_RO(buffSignatureToVerify, NULL, signature, sizeof(MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sv_status, sv_token, mcuxClSignature_verify(
    /* mcuxClSession_Handle_t session:  */ session,
    /* mcuxClKey_Handle_t key:          */ pubKey,
    /* mcuxClSignature_Mode_t mode:     */ mcuxClSignature_Mode_ECDSA,
    /* mcuxCl_InputBuffer_t pIn:        */ buffDigest,
    /* uint32_t inSize:                */ sizeof(digest),
    /* mcuxCl_InputBuffer_t pSignature: */ buffSignatureToVerify,
    /* uint32_t signatureSize:         */ signatureSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify) != sv_token) || (MCUXCLSIGNATURE_STATUS_OK != sv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Clean ecc verify session. */
  if(!mcuxClExample_Session_Clean(session))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
