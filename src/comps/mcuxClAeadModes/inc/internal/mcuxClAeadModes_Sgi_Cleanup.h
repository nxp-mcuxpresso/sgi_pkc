/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

/** @file  mcuxClAeadModes_Sgi_Cleanup.h
 *  @brief Internal cleanup function declaration for the mcuxClAeadModes component */

#ifndef MCUXCLAEADMODES_SGI_CLEANUP_H_
#define MCUXCLAEADMODES_SGI_CLEANUP_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <internal/mcuxClAeadModes_Common_Wa.h>
#include <internal/mcuxClAeadModes_Sgi_Ctx.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function to handle the normal exit for AEAD multipart.
 *
 * Use this function to leave highest-level mode functions in normal exit cases.
 * It flushes the SGI Key in context if not preloaded, frees CPU workarea and uninitializes the SGI.
 *
 * @param      session          Handle for the current CL session.
 * @param      pContext         Pointer to multipart context
 * @param[in]  cpuWaSizeInWords Number of cpu wa words to free
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAeadModes_cleanupOnMultipartExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_cleanupOnMultipartExit(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *pContext,
  uint32_t cpuWaSizeInWords);

/**
 * @brief Function to handle the normal exit for AEAD oneshot.
 *
 * Use this function to leave highest-level mode functions in normal exit cases.
 * It flushes the SGI Key if not preloaded, frees CPU workarea and uninitializes the SGI.
 *
 * @param      session          Handle for the current CL session.
 * @param      key              Handle for the key.
 * @param[in]  cpuWaSizeInWords Number of cpu wa words to free
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAeadModes_cleanupOnOneshotExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_cleanupOnOneshotExit(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /*MCUXCLAEADMODES_SGI_CLEANUP_H_*/
