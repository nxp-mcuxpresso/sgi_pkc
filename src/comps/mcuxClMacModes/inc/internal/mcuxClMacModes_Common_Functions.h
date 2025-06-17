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

/** @file  mcuxClMacModes_Common_Functions.h
 *  @brief Internal definitions of helper functions for the MacModes component
 */

#ifndef MCUXCLMACMODES_COMMON_FUNCTIONS_H_
#define MCUXCLMACMODES_COMMON_FUNCTIONS_H_

#include <mcuxCsslFlowProtection.h>
#include <mcuxClMac_Types.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSession_Types.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Skeleton functions for the MAC modes
 */

/**
 * @brief Mac Oneshot Compute mode function
 *
 * This function will perform the actual MAC compute operation based on the given mode
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_compute, mcuxClMac_ComputeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_compute(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClMac_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pMac,
  uint32_t * const pMacLength
);

/**
 * @brief MacModes Oneshot Compare dma-driven mode function
 *
 * This function will perform the actual dma-driven MAC compute operation based on the given mode,
 * blocking or non-blocking.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_compute_dmaDriven, mcuxClMac_ComputeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_compute_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClMac_Mode_t mode,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pMac,
  uint32_t * const pMacLength
);


/**
 * @brief MacModes Multipart Init mode function
 *
 * This function will perform the actual MAC init operation based on the given mode
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_init, mcuxClMac_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_init(
  mcuxClSession_Handle_t session,
  mcuxClMac_Context_t * const pContext,
  mcuxClKey_Handle_t key
);

/**
 * @brief MacModes Multipart Process mode function
 *
 * This function will perform the actual MAC process operation based on the given mode
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_process, mcuxClMac_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_process(
  mcuxClSession_Handle_t session,
  mcuxClMac_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength
);

/**
 * @brief MacModes Multipart Process dma-driven mode function
 *
 * This function will perform the actual dma-driven MAC process operation based on the given mode,
 * blocking or non-blocking.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_process_dmaDriven, mcuxClMac_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_process_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClMac_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength
);

/**
 * @brief MacModes Multipart Finish mode function
 *
 * This function will perform the actual MAC finish operation based on the given mode
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_finish, mcuxClMac_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_finish(
  mcuxClSession_Handle_t session,
  mcuxClMac_Context_t * const pContext,
  mcuxCl_Buffer_t pMac,
  uint32_t * const pMacLength
);



/** Inline function to convert word-aligned pointer to specific context. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_castPointerToContext)
static inline mcuxClMac_Context_t* mcuxClMacModes_castPointerToContext(uint32_t *pContext)
{
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClMac_Context_t* pCtx = (mcuxClMac_Context_t*)pContext;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    return pCtx;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMACMODES_COMMON_FUNCTIONS_H_ */
