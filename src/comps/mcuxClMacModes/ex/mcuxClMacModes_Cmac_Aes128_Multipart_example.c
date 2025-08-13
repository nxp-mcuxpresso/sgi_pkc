/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @example mcuxClMacModes_Cmac_Aes128_Multipart_example.c
 * @brief mcuxClMacModes example application
 */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClAes.h>
#include <mcuxClBuffer.h>
#include <mcuxClMac.h> // Interface to the entire mcuxClMac component
#include <mcuxClMacModes.h> // Interface to the entire mcuxClMacModes component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

#define MCUXCLMAC_CPU_WA_BUFFER_SIZE  (MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE + MCUXCLRANDOM_NCINIT_WACPU_SIZE)


/** NIST-SP800-38B Appendix D.1 test vectors */
static const uint8_t data[40] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11
};

static const uint8_t keyDataAes128[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const uint8_t cmacReferenceAes128[16] = {
    0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
    0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
};


MCUXCLEXAMPLE_FUNCTION(mcuxClMacModes_Cmac_Aes128_Multipart_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLMAC_CPU_WA_BUFFER_SIZE, 0u);

  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status, ki_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ key,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData                    */ keyDataAes128,
    /* uint32_t keyDataLength                */ sizeof(keyDataAes128))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) || (MCUXCLKEY_STATUS_OK != ki_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  /**************************************************************************/
  /* MAC Computation                                                        */
  /**************************************************************************/

  ALIGNED uint8_t ctxBuf[MCUXCLMAC_CONTEXT_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClMac_Context_t * ctx = (mcuxClMac_Context_t *) ctxBuf;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  uint8_t macData[sizeof(cmacReferenceAes128)];

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mi_status, mi_token, mcuxClMac_init(
    /* mcuxClSession_Handle_t session:       */ session,
    /* mcuxClMac_Context_t * const pContext: */ ctx,
    /* const mcuxClKey_Handle_t key:         */ key,
    /* mcuxClMac_Mode_t mode:                */ mcuxClMac_Mode_CMAC)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_init) != mi_token) || (MCUXCLMAC_STATUS_OK != mi_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_RO(dataBuff, session, data, sizeof(data));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mp1_status, mp1_token, mcuxClMac_process(
    /* mcuxClSession_Handle_t session:       */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClMac_init")
    /* mcuxClMac_Context_t * const pContext: */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:             */ dataBuff,
    /* uint32_t inLength:                   */ 5u)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_process) != mp1_token) || (MCUXCLMAC_STATUS_OK != mp1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_UPDATE(dataBuff, 5u);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mp2_status, mp2_token, mcuxClMac_process(
    /* mcuxClSession_Handle_t session:       */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClMac_init")
    /* mcuxClMac_Context_t * const pContext: */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:             */ dataBuff,  /* Only part of input data was processed */
    /* uint32_t inLength:                   */ sizeof(data) - 5u)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_process) != mp2_token) || (MCUXCLMAC_STATUS_OK != mp2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  uint32_t macSize = 0u;

  MCUXCLBUFFER_INIT(macDataBuf, session, macData, sizeof(macData));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mf_status, mf_token, mcuxClMac_finish(
    /* mcuxClSession_Handle_t session:       */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClMac_init")
    /* mcuxClMac_Context_t * const pContext: */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_Buffer_t pMac:                 */ macDataBuf,
    /* uint32_t * const pMacLength:         */ &macSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_finish) != mf_token) || (MCUXCLMAC_STATUS_OK != mf_status))
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

  if (macSize != sizeof(cmacReferenceAes128))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (!mcuxClCore_assertEqual(macData, cmacReferenceAes128, sizeof(cmacReferenceAes128)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
