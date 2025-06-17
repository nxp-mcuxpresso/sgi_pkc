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

/** @file  mcuxClCipherModes_Sgi_Types.h
 *  @brief Internal type definitions for the mcuxClCipherModes component
 */

#ifndef MCUXCLCIPHERMODES_SGI_TYPES_H_
#define MCUXCLCIPHERMODES_SGI_TYPES_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClAes.h>
#include <internal/mcuxClAes_Internal_Constants.h>
#include <internal/mcuxClAes_Ctx.h>
#include <mcuxClCore_Platform.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSession.h>

#include <internal/mcuxClPadding_Types_Internal.h>
#include <internal/mcuxClCipherModes_Common_Constants.h>
#include <internal/mcuxClCipherModes_Common_Wa.h>
#include <mcuxClCipher_Types.h>
#include <internal/mcuxClCipher_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Engine function type for "normal" blocking SGI modes
 * For stream ciphers (CTR), the engine is capable of processing incomplete blocks,
 * where only the actual amount of input bytes is copied to the @p pOut. The incomplete block is assumed to be the first one,
 * which means that a separate call to the engine for the last (potentially padded) block handling is needed.
 * @pre The provided @p inLength should be non-zero.
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipherModes_EngineFunc_AesSgi_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t)(*mcuxClCipherModes_EngineFunc_AesSgi_t) (
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t *pIvOut,
  uint32_t * const pOutLength
));

/**
 * @brief Engine function type for SGI modes that handles the wrap-up of AUTO mode (non-blocking)
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipherModes_completeAutoModeFunc_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void)(*mcuxClCipherModes_completeAutoModeFunc_t) (
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa
));

/**
 * @brief Finish function type for SGI modes
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipherModes_FinishFunc_AesSgi_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void)(*mcuxClCipherModes_FinishFunc_AesSgi_t) (
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
));

/**
 * @brief SetupIv function type for SGI modes
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipherModes_SetupIvFunc_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void)(*mcuxClCipherModes_SetupIvFunc_t) (
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIv
));

/**
 * @brief Function for checking length of the IV
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipherModes_CheckIvLength_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void)(*mcuxClCipherModes_CheckIvLength_t) (
  mcuxClSession_Handle_t session,
  uint32_t ivLength
));

/**
 * @brief Cipher context structure for SGI modes
 *
 * This structure is used in the mult-part interfaces to store the
 * information about the current operation and the relevant internal state.
 */
typedef struct mcuxClCipherModes_Context_Aes_Sgi
{
  mcuxClCipher_Context_t common;
  mcuxClCipherModes_SetupIvFunc_t        setupIV;
  uint32_t                              protectionToken_setupIV;
  mcuxClCipherModes_EngineFunc_AesSgi_t  processEngine;
  uint32_t                              protectionToken_processEngine;
  mcuxClCipherModes_FinishFunc_AesSgi_t  finishSkeleton;
  uint32_t                              protectionToken_finishSkeleton;
  uint8_t     blockBuffer[MCUXCLAES_BLOCK_SIZE];   /* Buffer used when not enough data for full block */
  uint32_t    ivState[MCUXCLAES_BLOCK_SIZE_IN_WORDS]; /* IV and internal state */
  mcuxClAes_KeyContext_Sgi_t keyContext;
  uint32_t direction; /* to differentiate between encryption and decryption */
} mcuxClCipherModes_Context_Aes_Sgi_t;

/**
 * @brief Cipher mode algorithm descriptor structure for AES algorithms using SGI
 *
 * This structure captures all the information that the Cipher interfaces need
 * to know about a SGI AES Cipher mode algorithm.
 */
typedef struct mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi
{
  mcuxClCipherModes_EngineFunc_AesSgi_t encryptEngine;
  uint32_t                             protectionToken_encryptEngine;
  mcuxClCipherModes_EngineFunc_AesSgi_t decryptEngine;
  uint32_t                             protectionToken_decryptEngine;
  mcuxClCipherModes_completeAutoModeFunc_t completeAutoModeEngine;
  uint32_t                                protectionToken_completeAutoModeEngine;
  mcuxClCipherModes_SetupIvFunc_t       setupIVEncrypt;
  uint32_t                             protectionToken_setupIVEncrypt;
  mcuxClCipherModes_SetupIvFunc_t       setupIVDecrypt;
  uint32_t                             protectionToken_setupIVDecrypt;
  mcuxClCipherModes_CheckIvLength_t     checkIvLength;
  uint32_t                             protectionToken_checkIvLength;
  mcuxClPadding_addPaddingMode_t        addPadding;
  uint32_t                             protectionToken_addPadding;
  mcuxClPadding_removePaddingMode_t     removePadding;
  uint32_t                             protectionToken_removePadding;
  uint32_t                             granularityEnc;
  uint32_t                             granularityDec;
} mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t;

/**
 * @brief Cipher mode algorithm type for "normal" blocking AES algorithms using SGI
 *
 * This type is used to refer to a SGI AES Cipher mode algorithm.
 */
typedef const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t * const mcuxClCipherModes_Algorithm_Aes_Sgi_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLCIPHERMODES_SGI_TYPES_H_ */
