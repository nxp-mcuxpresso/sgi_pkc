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

#ifndef MCUXCLCIPHERMODES_SGI_HELPER_H_
#define MCUXCLCIPHERMODES_SGI_HELPER_H_

#include <mcuxClSession_Types.h>
#include <internal/mcuxClCipherModes_Common_Wa.h>
#include <mcuxClSgi_Types.h>
#include <mcuxClDma_Types.h>

/* Function used to copy data from SGI to user */
/* Data Integrity: Expunge(outBuf + offset + mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET) + byteLength) */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_copyOut_toPtr, mcuxClSgi_copyOut_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_copyOut_toPtr(
  mcuxClSession_Handle_t session,
  void* pWa,
  mcuxCl_Buffer_t outBuf,
  uint32_t offset,
  uint32_t byteLength);


/*
 * Functions to handle the IV
 */

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_IV, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv
);

/**
 * @brief Function checks length of the IV for modes where inital vector is not needed.
 *
 * @param[in] ivLength          Length of the IV
 *
 * @return void
 * - returns (via early-exit) #MCUXCLCIPHER_STATUS_INVALID_INPUT  for length different than zero
*/
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_checkIvLen_noIv, mcuxClCipherModes_CheckIvLength_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_checkIvLen_noIv(
  mcuxClSession_Handle_t session,
  uint32_t ivLength);

/**
 * @brief Function checks length of the IV for modes where inital vector is needed.
 *
 * @param[in] ivLength          Length of the IV
 *
 * @return void
 * - returns (via early-exit) #MCUXCLCIPHER_STATUS_INVALID_INPUT  for length different than AES block
*/
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_checkIvLen, mcuxClCipherModes_CheckIvLength_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_checkIvLen(
  mcuxClSession_Handle_t session,
  uint32_t ivLength);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_No_IV, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_No_IV(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIv
);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_IV_AutoMode_Cbc_Dec, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_AutoMode_Cbc_Dec(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv
);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_IV_AutoMode_Ctr, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_AutoMode_Ctr(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv
);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_IV_to_DATOUT_DMA, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_to_DATOUT_DMA(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv
);


/*
 * DMA / AUTO-mode helper functions
 */
#define MCUXCLCIPHERMODES_REQUEST_DMA_CHANNELS(session, pWa, callbackFunction, callbackFunctionToken) \
  mcuxClDma_requestDmaInputAndOutputWithWorkarea((session), (pWa), (callbackFunction), callbackFunctionToken)


/**
 * @brief Internal function to load the key (SFR-masked) from the AES key context and IV to the SGI.
 *
 * If there is enough data to precess @p inLength together with data in context (pCtx->common.blockBufferUsed)
 * to process full block of data (MCUXCLAES_BLOCK_SIZE), this function will load the key (SFR-masked)
 * from the AES key context and IV to to the SGI.
 *
 * @param           session           Handle for the current session.
 * @param           pCtx              Pointer to AES context.
 * @param[in]       pWa               Pointer to cpu workarea
 * @param[in]       inLength          Length of input data
 * @param[out]      pKeyChecksum      Will be set to loaded key checksum in key was loaded
 *
 * @return void
*/
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_loadMaskedKeyAndIvtoSgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_loadMaskedKeyAndIvtoSgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx,
  mcuxClCipherModes_WorkArea_t * pWa,
  uint32_t inLength,
  mcuxClKey_KeyChecksum_t** pKeyChecksum
);

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_castToCipherModesContextAesSgi)
static inline mcuxClCipherModes_Context_Aes_Sgi_t* mcuxClCipherModes_castToCipherModesContextAesSgi(mcuxClCipher_Context_t* pContext)
{
  MCUX_CSSL_ANALYSIS_START_CAST_TO_MORE_SPECIFIC_TYPE()
  return (mcuxClCipherModes_Context_Aes_Sgi_t*) pContext;
  MCUX_CSSL_ANALYSIS_STOP_CAST_TO_MORE_SPECIFIC_TYPE()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_castToCipherModesWorkArea)
static inline mcuxClCipherModes_WorkArea_t* mcuxClCipherModes_castToCipherModesWorkArea(uint32_t* pWa)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClCipherModes_WorkArea_t *) pWa;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_castToCipherModesAlgorithmAesSgi)
static inline mcuxClCipherModes_Algorithm_Aes_Sgi_t mcuxClCipherModes_castToCipherModesAlgorithmAesSgi(const void* pAlgorithm)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClCipherModes_Algorithm_Aes_Sgi_t) pAlgorithm;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

#endif /* MCUXCLCIPHERMODES_SGI_HELPER_H_ */
