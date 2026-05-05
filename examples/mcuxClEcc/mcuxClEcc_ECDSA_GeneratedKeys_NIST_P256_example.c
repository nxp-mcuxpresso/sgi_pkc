/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @example mcuxClEcc_ECDSA_GeneratedKeys_NIST_P256_example.c
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
  0x39u, 0x3Bu, 0x4Bu, 0xEEu, 0xD5u, 0xDDu, 0x88u, 0x86u
};

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOM_NCINIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLSIGNATURE_SIGN_ECDSA_WACPU_SIZE, \
                                     MCUXCLSIGNATURE_VERIFY_ECDSA_WACPU_SIZE))))

#define MAX_PKCWA_SIZE MCUXCLCORE_MAX(MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_256, \
		                   MCUXCLCORE_MAX(MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_256, \
		                                 MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_256))

MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ECDSA_GeneratedKeys_NIST_P256_example)
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
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  ALIGNED uint8_t pPrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY];

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

  /* Allocate space for and initialize public key handle for an ECDSA NIST P-256 public key */
  uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  ALIGNED uint8_t pPubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY];

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
#if defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_256)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);
#elif defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_128)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES128_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES128_DRG3);
#else
  #error "Example not supported for target"
#endif


  /**************************************************************************/
  /* Key pair generation for ECDSA on NIST P-256                            */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(gkp_status, gkp_token, mcuxClKey_generate_keypair(
      /* mcuxClSession_Handle_t pSession:   */ session,
      /* mcuxClKey_Generation_t generation: */ mcuxClKey_Generation_ECDSA,
      /* mcuxClKey_Handle_t privKey:        */ privKey,
      /* mcuxClKey_Handle_t pubKey:         */ pubKey)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_generate_keypair) != gkp_token) || (MCUXCLKEY_STATUS_OK != gkp_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* ECDSA signature generation on NIST P-256                               */
  /**************************************************************************/

  uint8_t signature[MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE];
  MCUXCLBUFFER_INIT_RO(buffDigest, NULL, &digest[0], sizeof(digest));
  MCUXCLBUFFER_INIT(buffSignature, NULL, &signature[0], sizeof(MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE));
  uint32_t signatureSize = 0u;

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
  /* Record critical parameters for additional protection */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rp_status, rp_token, mcuxClSignature_verify_recordParam(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClSignature_Mode_t mode:    */ mcuxClSignature_Mode_ECDSA,
    /* mcuxCl_InputBuffer_t pIn:       */ buffDigest,
    /* uint32_t inSize:               */ sizeof(digest))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify_recordParam) != rp_token) || (MCUXCLSIGNATURE_STATUS_OK != rp_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_RO(buffSignatureIn, NULL, &signature[0], sizeof(MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sv_status, sv_token, mcuxClSignature_verify(
    /* mcuxClSession_Handle_t session:  */ session,
    /* mcuxClKey_Handle_t key:          */ pubKey,
    /* mcuxClSignature_Mode_t mode:     */ mcuxClSignature_Mode_ECDSA,
    /* mcuxCl_InputBuffer_t pIn:        */ buffDigest,
    /* uint32_t inSize:                */ sizeof(digest),
    /* mcuxCl_InputBuffer_t pSignature: */ buffSignatureIn,
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
