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

/** @file  mcuxClCipher_Internal_Types.h
 *  @brief Internal type definitions for the mcuxClCipher component */

#ifndef MCUXCLCIPHER_INTERNAL_TYPES_H_
#define MCUXCLCIPHER_INTERNAL_TYPES_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClCipher_Types.h>
#include <mcuxClBuffer.h>
#include <mcuxClSession.h>
#include <mcuxClKey_Types.h>

#include <internal/mcuxClResource_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Mode/Skeleton function types
 * Data Integrity (only when used for decrypt operation): Record(returnCode)
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipher_CryptFunc_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) (*mcuxClCipher_CryptFunc_t) (
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t pKey,
  mcuxClCipher_Mode_t pMode,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
));

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipher_InitFunc_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void)(*mcuxClCipher_InitFunc_t) (
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxClKey_Handle_t pKey,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength
));

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipher_ProcessFunc_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t)(*mcuxClCipher_ProcessFunc_t) (
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
));

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClCipher_FinishFunc_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void)(*mcuxClCipher_FinishFunc_t) (
  mcuxClSession_Handle_t session,
  mcuxClCipher_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
));


/**
 * @brief Macros for @ref mcuxClCipher_ModeFunctions_t
 */
#define MCUXCLCIPHER_ENCRYPT_DECRYPT_ONESHOT_MODEFUNCTIONS \
  mcuxClCipher_CryptFunc_t       encrypt; \
  mcuxClCipher_CryptFunc_t       decrypt; \
  uint32_t                      protection_token_encrypt; \
  uint32_t                      protection_token_decrypt;

#define MCUXCLCIPHER_ENCRYPT_DECRYPT_MULTIPART_MODEFUNCTIONS \
  mcuxClCipher_InitFunc_t        initEncrypt; \
  mcuxClCipher_InitFunc_t        initDecrypt; \
  mcuxClCipher_ProcessFunc_t     process; \
  mcuxClCipher_FinishFunc_t      finish; \
  uint32_t                      protection_token_initencrypt; \
  uint32_t                      protection_token_initdecrypt; \
  uint32_t                      protection_token_process; \
  uint32_t                      protection_token_finish;


/**
 * @brief Cipher mode function structure
 *
 * This structure captures all the information related to the functions
 * of the Cipher interfaces.
 */
typedef struct mcuxClCipher_ModeFunctions
{
  MCUXCLCIPHER_ENCRYPT_DECRYPT_ONESHOT_MODEFUNCTIONS
  MCUXCLCIPHER_ENCRYPT_DECRYPT_MULTIPART_MODEFUNCTIONS
} mcuxClCipher_ModeFunctions_t;

/**
 * @brief Cipher mode/algorithm descriptor structure
 *
 * This structure captures all the information that the Cipher interfaces need
 * to know about a particular Cipher mode/algorithm.
 */
struct mcuxClCipher_ModeDescriptor
{
  const void *pModeFunctions;
  void *      pAlgorithm;
};

/**
 * @brief Cipher context structure
 *
 * This structure is used in the multi-part interfaces to store the
 * information about the current operation and the relevant internal state.
 * This is the common part of the context needed by cipher modes.
 */
struct mcuxClCipher_Context
{
  uint32_t    contextCrc;
  const mcuxClCipher_ModeDescriptor_t * pMode;

  uint32_t blockBufferUsed; /* How many bytes in blockBuffer is used */
  uint32_t totalInputLength;/* Total number of bytes that were encrypted */
};


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLCIPHER_INTERNAL_TYPES_H_ */
