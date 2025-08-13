/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @example mcuxClEcc_ECDSA_VerifyOnly_NIST_P256_example.c
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
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

static const uint8_t data[] = {
  0xCAu, 0x83u, 0x5Fu, 0x5Bu, 0x0Bu, 0x44u, 0x33u, 0x32u, 0x11u, 0x4Eu, 0xEAu, 0xA5u, 0x9Au, 0xE5u, 0x56u, 0x7Eu, 0x4Fu, 0x86u, 0xAFu, 0x72u, 0xF1u, 0x1Cu, 0xB4u, 0xE6u, 0x71u, 0xD9u, 0x13u, 0xDEu, 0x03u, 0xD4u, 0xC5u, 0xB7u
};

static const ALIGNED uint8_t pubKeyBytes[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {
  0xE8u, 0x19u, 0xC6u, 0x90u, 0x80u, 0xFEu, 0x45u, 0x2Fu,
  0x12u, 0x3Du, 0xA0u, 0x2Cu, 0xC7u, 0xB1u, 0x8Du, 0x54u,
  0xE1u, 0x83u, 0x95u, 0x82u, 0xF9u, 0xF4u, 0x0Du, 0x90u,
  0xBBu, 0x77u, 0xF3u, 0x8Cu, 0x60u, 0x84u, 0x37u, 0xC6u,
  0x85u, 0x62u, 0xAAu, 0xA4u, 0x8Du, 0x2Du, 0x61u, 0x1Fu,
  0xF1u, 0xEFu, 0x58u, 0x50u, 0x6Bu, 0x08u, 0xC2u, 0x62u,
  0x01u, 0x2Bu, 0xC0u, 0xC1u, 0x3Eu, 0xD7u, 0x37u, 0x72u,
  0x44u, 0x65u, 0xB3u, 0x2Cu, 0x02u, 0x79u, 0x85u, 0x9Au
  };

  static const uint8_t signature[MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE] = {
    //R
    0x28u, 0xF7u, 0xA7u, 0x1Au, 0xADu, 0xEAu, 0x35u, 0x2Au,
    0x41u, 0x33u, 0xB5u, 0x3Au, 0x79u, 0x1Cu, 0x69u, 0x33u,
    0x38u, 0x2Au, 0xE3u, 0x74u, 0xBDu, 0xA7u, 0xB6u, 0x50u,
    0x20u, 0xE0u, 0xF6u, 0x8Du, 0x1Bu, 0x1Bu, 0x35u, 0x46u,
    //S
    0xF8u, 0x61u, 0x71u, 0x93u, 0xA9u, 0x3Au, 0xB6u, 0x22u,
    0xD0u, 0x03u, 0xBFu, 0xC0u, 0x77u, 0xB8u, 0x41u, 0xD9u,
    0x91u, 0xDFu, 0xFCu, 0xC5u, 0xEFu, 0x34u, 0xE2u, 0x53u,
    0xBFu, 0xB5u, 0x9Eu, 0xA7u, 0xC7u, 0xAFu, 0x40u, 0x13u

  };

#define MAX_CPUWA_SIZE MCUXCLSIGNATURE_VERIFY_ECDSA_WACPU_SIZE
#define MAX_PKCWA_SIZE MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_256

MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ECDSA_VerifyOnly_NIST_P256_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /* Setup one session to be used by all functions called */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

  uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_status, ki_pub_token, mcuxClKey_init(
   /* mcuxClSession_Handle_t session         */ session,
   /* mcuxClKey_Handle_t key                 */ pubKey,
   /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_WeierECC_NIST_P256_Pub,
   /* const uint8_t * pKeyData              */ pubKeyBytes,
   /* uint32_t keyDataLength                */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* Signature Verification                                                 */
  /**************************************************************************/
  MCUXCLBUFFER_INIT_RO(buffData, NULL, data, sizeof(data));
  MCUXCLBUFFER_INIT_RO(buffSignature, NULL, signature, sizeof(signature));
  /* Record critical parameters for additional protection */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rp_status, rp_token, mcuxClSignature_verify_recordParam(
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION")
    /* mcuxClSession_Handle_t session: */ session,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxClSignature_Mode_t mode:    */ mcuxClSignature_Mode_ECDSA,
    /* mcuxCl_InputBuffer_t pIn:       */ buffData,
    /* uint32_t inSize:               */ sizeof(data))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify_recordParam) != rp_token) || (MCUXCLSIGNATURE_STATUS_OK != rp_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sv_status, sv_token, mcuxClSignature_verify(
   /* mcuxClSession_Handle_t session:  */ session,
   /* mcuxClKey_Handle_t key:          */ pubKey,
   /* mcuxClSignature_Mode_t mode:     */ mcuxClSignature_Mode_ECDSA,
   /* mcuxCl_InputBuffer_t pIn:        */ buffData,
   /* uint32_t inSize:                */ sizeof(data),
   /* mcuxCl_InputBuffer_t pSignature: */ buffSignature,
   /* uint32_t signatureSize:         */ sizeof(signature))
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
