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
 * @example mcuxClAeadModes_Ccm_Aes128_Oneshot_Nist1_example.c
 * @brief   Example for the mcuxClAeadModes component
 */

#include <mcuxClBuffer.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClAead.h>
#include <mcuxClAeadModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClAes.h>
#include <mcuxClExample_RNG_Helper.h>

/* NIST Special Publication 800-38C example 1 test vectors */
static const uint8_t plain[4] = {
  0x20U, 0x21U, 0x22U, 0x23U
};

static const uint8_t adata[8] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U
};

static const uint8_t nonce[7] = {
  0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U
};

static const uint8_t keyBytes[16] = {
  0x40U, 0x41U, 0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U,
  0x48U, 0x49U, 0x4aU, 0x4bU, 0x4cU, 0x4dU, 0x4eU, 0x4fU
};

static const uint8_t tagReference[4] = {
  0x4dU, 0xacU, 0x25U, 0x5dU
};

static const uint8_t encryptedReference[4] = {
  0x71U, 0x62U, 0x01U, 0x5bU
};



MCUXCLEXAMPLE_FUNCTION(mcuxClAeadModes_Ccm_Aes128_Oneshot_Nist1_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  MCUXCLBUFFER_INIT_RO(plainBuf, session, plain, sizeof(plain));
  MCUXCLBUFFER_INIT_RO(adataBuf, session, adata, sizeof(adata));
  MCUXCLBUFFER_INIT_RO(nonceBuf, session, nonce, sizeof(nonce));

  #define maxBufferSize (((MCUXCLAEAD_ENCRYPT_CPU_WA_BUFFER_SIZE > MCUXCLAEAD_DECRYPT_CPU_WA_BUFFER_SIZE) ? \
                                 MCUXCLAEAD_ENCRYPT_CPU_WA_BUFFER_SIZE : MCUXCLAEAD_DECRYPT_CPU_WA_BUFFER_SIZE) + MCUXCLRANDOM_NCINIT_WACPU_SIZE)

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, maxBufferSize, 0U);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;
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
  /* One-shot Encryption                                                    */
  /**************************************************************************/
  uint32_t encryptedOneShotSize = 0U;
  uint8_t encryptedOneshotData[sizeof(encryptedReference)];
  MCUXCLBUFFER_INIT(encryptedOneshotDataBuf, session, encryptedOneshotData, sizeof(encryptedOneshotData));
  uint8_t tagOneshotData[sizeof(tagReference)];
  MCUXCLBUFFER_INIT(tagOneshotDataBuf, session, tagOneshotData, sizeof(tagOneshotData));

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(e_status, e_token, mcuxClAead_encrypt(
    /* mcuxClSession_Handle_t session:        */ session,
    /* const mcuxClKey_Handle_t key:          */ key,
    /* const mcuxClAead_Mode_t * const mode:  */ mcuxClAead_Mode_CCM,
    /* mcuxCl_InputBuffer_t nonce             */ nonceBuf,
    /* uint32_t nonceSize,                   */ sizeof(nonce),
    /* mcuxCl_InputBuffer_t in                */ plainBuf,
    /* uint32_t inSize,                      */ sizeof(plain),
    /* mcuxCl_InputBuffer_t adata             */ adataBuf,
    /* uint32_t adataSize,                   */ sizeof(adata),
    /* mcuxCl_Buffer_t out,                   */ encryptedOneshotDataBuf,
    /* uint32_t * const outSize              */ &encryptedOneShotSize,
    /* mcuxCl_Buffer_t tag,                   */ tagOneshotDataBuf,
    /* const uint32_t tagSize,               */ sizeof(tagReference))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_encrypt) != e_token) || (MCUXCLAEAD_STATUS_OK != e_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* One-shot Decryption                                                    */
  /**************************************************************************/
  uint32_t decryptedOneshotSize = 0U;
  uint8_t decryptedOneshotData[sizeof(plain)];
  MCUXCLBUFFER_INIT(decryptedOneshotDataBuf, session, decryptedOneshotData, sizeof(decryptedOneshotData));

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(d_status, d_token, mcuxClAead_decrypt(
    /* mcuxClSession_Handle_t session:       */ session,
    /* const mcuxClKey_Handle_t key:         */ key,
    /* const mcuxClAead_Mode_t * const mode: */ mcuxClAead_Mode_CCM,
    /* mcuxCl_InputBuffer_t nonce,           */ nonceBuf,
    /* const uint32_t nonceSize,            */ sizeof(nonce),
    /* mcuxCl_InputBuffer_t in               */ encryptedOneshotDataBuf,
    /* uint32_t inSize,                     */ encryptedOneShotSize,
    /* mcuxCl_InputBuffer_t adata            */ adataBuf,
    /* const uint32_t adataSize,            */ sizeof(adata),
    /* mcuxCl_Buffer_t tag,                  */ tagOneshotDataBuf,
    /* const uint32_t tagSize,              */ sizeof(tagReference),
    /* mcuxCl_Buffer_t out,                  */ decryptedOneshotDataBuf,
    /* uint32_t * const outSize             */ &decryptedOneshotSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_decrypt) != d_token) || (MCUXCLAEAD_STATUS_OK != d_status))
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

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT")
  if (!mcuxClCore_assertEqual(encryptedOneshotData, encryptedReference, sizeof(encryptedReference)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT")
  if (!mcuxClCore_assertEqual(tagOneshotData, tagReference, sizeof(tagReference)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  if (sizeof(encryptedReference) != encryptedOneShotSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (!mcuxClCore_assertEqual(plain, decryptedOneshotData, sizeof(plain)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (sizeof(plain) != decryptedOneshotSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
