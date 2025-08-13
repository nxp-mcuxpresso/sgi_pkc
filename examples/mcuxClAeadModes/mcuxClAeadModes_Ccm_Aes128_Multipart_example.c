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
 * @example mcuxClAeadModes_Ccm_Aes128_Multipart_example.c
 * @brief   Example for the mcuxClAeadModes component
 */

#include <mcuxClCore_Examples.h>
#include <mcuxClBuffer.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClAead.h>
#include <mcuxClAeadModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClAes.h>
#include <mcuxClExample_RNG_Helper.h>

static const uint8_t plain[24] = {
  0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U,
  0x28U, 0x29U, 0x2aU, 0x2bU, 0x2cU, 0x2dU, 0x2eU, 0x2fU,
  0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U
};

static const uint8_t adata[20] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
  0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
  0x10U, 0x11U, 0x12U, 0x13U
};

static const uint8_t nonce[12] = {
  0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
  0x18U, 0x19U, 0x1aU, 0x1bU
};

static const uint8_t keyBytes[16] = {
  0x40U, 0x41U, 0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U,
  0x48U, 0x49U, 0x4aU, 0x4bU, 0x4cU, 0x4dU, 0x4eU, 0x4fU
};

static const uint8_t tagReference[8] = {
  0x48U, 0x43U, 0x92U, 0xfbU, 0xc1U, 0xb0U, 0x99U, 0x51U
};

static const uint8_t encryptedReference[24] = {
  0xe3U, 0xb2U, 0x01U, 0xa9U, 0xf5U, 0xb7U, 0x1aU, 0x7aU,
  0x9bU, 0x1cU, 0xeaU, 0xecU, 0xcdU, 0x97U, 0xe7U, 0x0bU,
  0x61U, 0x76U, 0xaaU, 0xd9U, 0xa4U, 0x42U, 0x8aU, 0xa5U
};

MCUXCLEXAMPLE_FUNCTION(mcuxClAeadModes_Ccm_Aes128_Multipart_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  MCUXCLBUFFER_INIT_RO(plainBuf, session, plain, sizeof(plain));
  MCUXCLBUFFER_INIT_RO(adataBuf, session, adata, sizeof(adata));
  MCUXCLBUFFER_INIT_RO(nonceBuf, session, nonce, sizeof(nonce));

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLAEAD_MAX_CPU_WA_BUFFER_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0U);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status, ki_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ key,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData                    */ keyBytes,
    /* uint32_t keyDataLength                */ sizeof(keyBytes))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) || (MCUXCLKEY_STATUS_OK != ki_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Multi-part Encryption                                                  */
  /**************************************************************************/

  uint32_t encryptedSize = 0U;
  uint32_t encryptedMultipartSize = 0U;
  uint8_t encryptedMultipartData[sizeof(encryptedReference)];
  MCUXCLBUFFER_INIT(encryptedMultipartDataBuf, session, encryptedMultipartData, sizeof(encryptedMultipartData));
  uint8_t tagMultipartData[sizeof(tagReference)];
  MCUXCLBUFFER_INIT(tagMultipartDataBuf, session, tagMultipartData, sizeof(tagMultipartData));

  uint8_t ctxBuf[MCUXCLAEAD_CONTEXT_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClAead_Context_t * ctx = (mcuxClAead_Context_t *) ctxBuf;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ei_status, ei_token, mcuxClAead_init_encrypt(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    /* mcuxClKey_Handle_t key                 */ key,
    /* mcuxClAead_Mode_t mode                 */ mcuxClAead_Mode_CCM,
    /* mcuxCl_InputBuffer_t pNonce            */ nonceBuf,
    /* uint32_t nonceSize,                   */ sizeof(nonce),
    /* uint32_t inSize,                      */ sizeof(plain),
    /* uint32_t adataSize,                   */ sizeof(adata),
    /* uint32_t tagSize,                     */ sizeof(tagReference))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_init_encrypt) != ei_token) || (MCUXCLAEAD_STATUS_OK != ei_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /*
   * mcuxClAead_process_adata() processes the header data. This needs to be completed
   * before other data can be processed. Therefore all calls to mcuxClAead_process_adata()
   * need to be made before calls to mcuxClAead_process().
   */

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(epa1_status, epa1_token, mcuxClAead_process_adata(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_encrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pAdata            */ adataBuf,
    /* uint32_t adataSize                    */ sizeof(adata)/3U)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process_adata) != epa1_token) || (MCUXCLAEAD_STATUS_OK != epa1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_UPDATE(adataBuf, sizeof(adata)/3U);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(epa2_status, epa2_token, mcuxClAead_process_adata(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_encrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pAdata            */ adataBuf,  /* Only part of input data was processed */
    /* uint32_t adataSize                    */ sizeof(adata) - sizeof(adata)/3U)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process_adata) != epa2_token) || (MCUXCLAEAD_STATUS_OK != epa2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ep1_status, ep1_token, mcuxClAead_process(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_encrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn               */ plainBuf,
    /* uint32_t inSize                       */ sizeof(plain)/2U,
    /* mcuxCl_Buffer_t pOut                   */ encryptedMultipartDataBuf,
    /* uint32_t * const pOutSize             */ &encryptedSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process) != ep1_token) || (MCUXCLAEAD_STATUS_OK != ep1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  encryptedMultipartSize += encryptedSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUXCLBUFFER_UPDATE(plainBuf, sizeof(plain)/2U);
  MCUXCLBUFFER_DERIVE_RW(encryptedMultipartDataBuf2, encryptedMultipartDataBuf, encryptedMultipartSize);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ep2_status, ep2_token, mcuxClAead_process(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_encrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn               */ plainBuf,  /* Only part of input data was processed */
    /* uint32_t inSize                       */ sizeof(plain) - sizeof(plain)/2U,
    /* mcuxCl_Buffer_t pOut                   */ encryptedMultipartDataBuf2,
    /* uint32_t * const pOutSize             */ &encryptedSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process) != ep2_token) || (MCUXCLAEAD_STATUS_OK != ep2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  encryptedMultipartSize += encryptedSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUXCLBUFFER_DERIVE_RW(encryptedMultipartDataBuf3, encryptedMultipartDataBuf, encryptedMultipartSize);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ef_status, ef_token, mcuxClAead_finish(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_encrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_Buffer_t pOut                   */ encryptedMultipartDataBuf3,
    /* uint32_t * const pOutSize             */ &encryptedSize,
    /* mcuxCl_Buffer_t pTag                   */ tagMultipartDataBuf)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_finish) != ef_token) || (MCUXCLAEAD_STATUS_OK != ef_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  encryptedMultipartSize += encryptedSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  /**************************************************************************/
  /* Multi-part Decryption                                                  */
  /**************************************************************************/

  uint32_t decryptedSize = 0U;
  uint32_t decryptedMultipartSize = 0U;
  uint8_t decryptedMultipartData[sizeof(plain)];
  MCUXCLBUFFER_INIT(decryptedMultipartDataBuf, session, decryptedMultipartData, sizeof(decryptedMultipartData));

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(di_status, di_token, mcuxClAead_init_decrypt(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    /* mcuxClKey_Handle_t key                 */ key,
    /* mcuxClAead_Mode_t mode                 */ mcuxClAead_Mode_CCM,
    /* mcuxCl_InputBuffer_t pNonce            */ nonceBuf,
    /* uint32_t nonceSize,                   */ sizeof(nonce),
    /* uint32_t inSize,                      */ sizeof(plain),
    /* uint32_t adataSize,                   */ sizeof(adata),
    /* uint32_t tagSize,                     */ sizeof(tagReference))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_init_decrypt) != di_token) || (MCUXCLAEAD_STATUS_OK != di_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_RO(adataBuf2, session, adata, sizeof(adata));

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dpa1_status, dpa1_token, mcuxClAead_process_adata(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_decrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pAdata            */ adataBuf2,
    /* uint32_t adataSize                    */ sizeof(adata)/2U)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process_adata) != dpa1_token) || (MCUXCLAEAD_STATUS_OK != dpa1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_UPDATE(adataBuf2, sizeof(adata)/2U);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dpa2_status, dpa2_token, mcuxClAead_process_adata(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_decrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pAdata            */ adataBuf2,  /* Only part of input data was processed */
    /* uint32_t adataSize                    */ sizeof(adata) - sizeof(adata)/2U)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process_adata) != dpa2_token) || (MCUXCLAEAD_STATUS_OK != dpa2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_DERIVE_RO(encryptedMultipartData_InBuf, encryptedMultipartDataBuf, 0);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dp1_status, dp1_token, mcuxClAead_process(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_decrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_DERIVE_RO")
    /* mcuxCl_InputBuffer_t pIn               */ encryptedMultipartData_InBuf,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* uint32_t inSize                       */ encryptedMultipartSize/2U,
    /* mcuxCl_Buffer_t pOut                   */ decryptedMultipartDataBuf,
    /* uint32_t * const pOutSize             */ &decryptedMultipartSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process) != dp1_token) || (MCUXCLAEAD_STATUS_OK != dp1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  decryptedMultipartSize += decryptedSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUXCLBUFFER_UPDATE(encryptedMultipartData_InBuf, encryptedMultipartSize/2U);
  MCUXCLBUFFER_DERIVE_RW(decryptedMultipartDataBuf2, decryptedMultipartDataBuf, decryptedMultipartSize);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dp2_status, dp2_token, mcuxClAead_process(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_decrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_DERIVE_RO")
    /* mcuxCl_InputBuffer_t pIn               */ encryptedMultipartData_InBuf,  /* Only part of input data was processed */
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not wrap")
    /* uint32_t inSize                       */ encryptedMultipartSize - encryptedMultipartSize/2U,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    /* mcuxCl_Buffer_t pOut                   */ decryptedMultipartDataBuf2,
    /* uint32_t * const pOutSize             */ &decryptedSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process) != dp2_token) || (MCUXCLAEAD_STATUS_OK != dp2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  decryptedMultipartSize += decryptedSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUXCLBUFFER_DERIVE_RW(decryptedMultipartDataBuf3, decryptedMultipartDataBuf, decryptedMultipartSize);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dv_status, dv_token, mcuxClAead_verify(
    /* mcuxClSession_Handle_t session         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClAead_init_decrypt")
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pTag              */ tagMultipartDataBuf,
    /* mcuxCl_Buffer_t pOut                   */ decryptedMultipartDataBuf3,
    /* uint32_t * const pOutSize             */ &decryptedSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_verify) != dv_token) || (MCUXCLAEAD_STATUS_OK != dv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  decryptedMultipartSize += decryptedSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

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

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initilized by MCUXCLBUFFER_INIT")
  if (!mcuxClCore_assertEqual(encryptedMultipartData, encryptedReference, sizeof(encryptedReference)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initilized by MCUXCLBUFFER_INIT")
  if (!mcuxClCore_assertEqual(tagMultipartData, tagReference, sizeof(tagReference)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  if (sizeof(encryptedReference) != encryptedMultipartSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (!mcuxClCore_assertEqual(plain, decryptedMultipartData, sizeof(plain)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (sizeof(plain) != decryptedMultipartSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
