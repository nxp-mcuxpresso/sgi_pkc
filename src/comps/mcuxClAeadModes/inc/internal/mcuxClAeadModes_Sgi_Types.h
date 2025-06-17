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

/** @file  mcuxClAeadModes_Sgi_Types.h
 *  @brief Internal defines of types for the mcuxClAeadModes component
*/

#ifndef MCUXCLAEADMODES_SGI_TYPES_H_
#define MCUXCLAEADMODES_SGI_TYPES_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>

#include <internal/mcuxClAead_Descriptor.h>
#include <internal/mcuxClAeadModes_Common_Wa.h>

#include <internal/mcuxClMacModes_Sgi_Types.h>
#include <internal/mcuxClCipherModes_Sgi_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward Declarations for context struct types */
struct mcuxClAeadModes_Context;
typedef struct mcuxClAeadModes_Context mcuxClAeadModes_Context_t;

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClAeadModes_alg_init_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClAeadModes_alg_init_t)(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *const pContext,
  mcuxClAeadModes_WorkArea_t *workArea,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceSize,
  uint32_t inSize,
  uint32_t adataSize,
  uint32_t tagSize)
);

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClAeadModes_alg_process_aad_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClAeadModes_alg_process_aad_t)(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *const pContext,
  mcuxClAeadModes_WorkArea_t *workArea,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataSize)
);

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClAeadModes_alg_process_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClAeadModes_alg_process_t)(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *const pContext,
  mcuxClAeadModes_WorkArea_t *workArea,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxCl_Buffer_t pOut,
  uint32_t *const pOutSize)
);

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClAeadModes_ProcessFullBlocks_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClAeadModes_ProcessFullBlocks_t)(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *const pContext,
  mcuxClAeadModes_WorkArea_t *workArea,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  const uint32_t inSize)
);

MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClAeadModes_alg_finish_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClAeadModes_alg_finish_t)(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *const pContext,
  mcuxClAeadModes_WorkArea_t *workArea,
  mcuxCl_Buffer_t pOut,
  uint32_t *const pOutSize,
  mcuxCl_Buffer_t pTag));

typedef struct mcuxClAead_AlgorithmDescriptor
{
  mcuxClAeadModes_alg_init_t init;
  uint32_t protectionToken_init;
  mcuxClAeadModes_alg_process_aad_t processAad;
  uint32_t protectionToken_processAad;
  mcuxClAeadModes_alg_process_t processEncDec;
  uint32_t protectionToken_processEncDec;
  mcuxClAeadModes_ProcessFullBlocks_t processFullBlocks;
  uint32_t protectionToken_processFullBlocks;
  mcuxClAeadModes_alg_finish_t finish;
  uint32_t protectionToken_finish;
  uint32_t mode;

  const mcuxClMacModes_AlgorithmDescriptor_t * macAlgo;
  const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t * cipherAlgo;
} mcuxClAeadModes_AlgorithmDescriptor_t;


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAEADMODES_SGI_TYPES_H_ */
