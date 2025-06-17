/*--------------------------------------------------------------------------*/
/* Copyright 2020-2024 NXP                                                  */
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
 * @example mcuxClAeadModes_Gcm_Aes128_Multipart_example.c
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

static const uint8_t plain[] = {
  0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
  0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU
};

static const uint8_t adata[] = {
  0xcaU, 0xeaU, 0x07U, 0x26U, 0x62U, 0xe2U, 0x20U, 0x06U,
  0x2dU, 0x45U, 0x46U, 0x41U, 0x5eU, 0xffU, 0xfaU, 0xd2U
};

static const uint8_t nonce[] = {
  0xf8U, 0xd2U, 0x68U, 0x76U, 0x81U, 0x6fU, 0x0fU, 0xbaU,
  0x86U, 0x2bU, 0xd8U, 0xa3U
};

static const uint8_t keyBytes[] = {
  0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
  0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
};

static const uint8_t tagReference[] = {
  0xb2U, 0xc5U, 0xcfU, 0xc3U, 0xf2U, 0x8cU, 0x9fU, 0x78U,
  0xfcU, 0x25U, 0xbcU, 0x10U, 0xc9U, 0xcaU, 0xffU, 0xd5U
};

static const uint8_t encryptedReference[] = {
  0x4fU, 0x74U, 0x2dU, 0xf6U, 0x9dU, 0x1cU, 0x03U, 0x6bU,
  0x56U, 0xbcU, 0xc2U, 0x81U, 0x5fU, 0xdaU, 0x8dU, 0x6dU
};

MCUXCLEXAMPLE_FUNCTION(mcuxClAeadModes_Gcm_Aes128_Multipart_example)
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
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status, ki_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ key,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData                    */ (uint8_t *) keyBytes,
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
  mcuxClAead_Context_t * ctx = (mcuxClAead_Context_t *) ctxBuf;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ei_status, ei_token, mcuxClAead_init_encrypt(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    /* mcuxClKey_Handle_t key                 */ key,
    /* mcuxClAead_Mode_t mode                 */ mcuxClAead_Mode_GCM,
    /* mcuxCl_InputBuffer_t pNonce            */ nonceBuf,
    /* uint32_t nonceSize,                   */ sizeof(nonce),
    /* uint32_t inSize,                      */ 0U /* unused during GCM init */,
    /* uint32_t adataSize,                   */ 0U /* unused during GCM init */,
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
    /* mcuxClAead_Context_t * const pContext  */ ctx,
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
    /* mcuxClAead_Context_t * const pContext  */ ctx,
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
    /* mcuxClAead_Context_t * const pContext  */ ctx,
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

  encryptedMultipartSize += encryptedSize;

  MCUXCLBUFFER_UPDATE(plainBuf, sizeof(plain)/2U);
  MCUXCLBUFFER_DERIVE_RW(encryptedMultipartDataBuf2, encryptedMultipartDataBuf, encryptedMultipartSize);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ep2_status, ep2_token, mcuxClAead_process(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClAead_Context_t * const pContext  */ ctx,
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

  encryptedMultipartSize += encryptedSize;

  MCUXCLBUFFER_DERIVE_RW(encryptedMultipartDataBuf3, encryptedMultipartDataBuf, encryptedMultipartSize);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ef_status, ef_token, mcuxClAead_finish(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    /* mcuxCl_Buffer_t pOut                   */ encryptedMultipartDataBuf3,
    /* uint32_t * const pOutSize             */ &encryptedSize,
    /* mcuxCl_Buffer_t pTag                   */ tagMultipartDataBuf)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_finish) != ef_token) || (MCUXCLAEAD_STATUS_OK != ef_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  encryptedMultipartSize += encryptedSize;

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
    /* mcuxClAead_Mode_t mode                 */ mcuxClAead_Mode_GCM,
    /* mcuxCl_InputBuffer_t pNonce            */ nonceBuf,
    /* uint32_t nonceSize,                   */ sizeof(nonce),
    /* uint32_t inSize,                      */ 0U /* unused during GCM init */,
    /* uint32_t adataSize,                   */ 0U /* unused during GCM init */,
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
    /* mcuxClAead_Context_t * const pContext  */ ctx,
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
    /* mcuxClAead_Context_t * const pContext  */ ctx,
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
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    /* mcuxCl_InputBuffer_t pIn               */ encryptedMultipartData_InBuf,
    /* uint32_t inSize                       */ encryptedMultipartSize/2U,
    /* mcuxCl_Buffer_t pOut                   */ decryptedMultipartDataBuf,
    /* uint32_t * const pOutSize             */ &decryptedMultipartSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process) != dp1_token) || (MCUXCLAEAD_STATUS_OK != dp1_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_UPDATE(encryptedMultipartData_InBuf, encryptedMultipartSize/2U);
  MCUXCLBUFFER_DERIVE_RW(decryptedMultipartDataBuf2, decryptedMultipartDataBuf, decryptedMultipartSize);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dp2_status, dp2_token, mcuxClAead_process(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    /* mcuxCl_InputBuffer_t pIn               */ encryptedMultipartData_InBuf,  /* Only part of input data was processed */
    /* uint32_t inSize                       */ encryptedMultipartSize - encryptedMultipartSize/2U,
    /* mcuxCl_Buffer_t pOut                   */ decryptedMultipartDataBuf2,
    /* uint32_t * const pOutSize             */ &decryptedSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process) != dp2_token) || (MCUXCLAEAD_STATUS_OK != dp2_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  decryptedMultipartSize += decryptedSize;

  MCUXCLBUFFER_DERIVE_RW(decryptedMultipartDataBuf3, decryptedMultipartDataBuf, decryptedMultipartSize);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dv_status, dv_token, mcuxClAead_verify(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClAead_Context_t * const pContext  */ ctx,
    /* mcuxCl_InputBuffer_t pTag              */ tagMultipartDataBuf,
    /* mcuxCl_Buffer_t pOut                   */ decryptedMultipartDataBuf3,
    /* uint32_t * const pOutSize             */ &decryptedSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_verify) != dv_token) || (MCUXCLAEAD_STATUS_OK != dv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  decryptedMultipartSize += decryptedSize;

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

  if (!mcuxClCore_assertEqual(encryptedMultipartData, encryptedReference, sizeof(encryptedReference)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (!mcuxClCore_assertEqual(tagMultipartData, tagReference, sizeof(tagReference)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

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
