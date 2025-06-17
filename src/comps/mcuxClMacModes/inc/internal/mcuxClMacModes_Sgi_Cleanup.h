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

#ifndef MCUXCLMACMODES_SGI_CLEANUP_H_
#define MCUXCLMACMODES_SGI_CLEANUP_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <internal/mcuxClMac_Ctx.h>
#include <internal/mcuxClMac_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Function to handle OK and ERROR/FAILURE exit
 *
 * Use this function to leave functions in _not_ FAULT_ATTACK cases.
 * It frees CPU workarea and uninitializes the SGI.
 *
 * @param      session          Handle for the current CL session.
 * @param      pContext         Pointer to multipart context
 * @param      key              Handle for the key.
 *                              If the key is in the context, this param shall be NULL.
 * @param[in]  cpuWaSizeInWords Number of cpu wa words to free
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_cleanupOnExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_cleanupOnExit(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_Context_t *pContext,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords);


/**
 * @brief Function to handle OK and ERROR/FAILURE exit
 *
 * Use this function to leave functions in _not_ FAULT_ATTACK cases.
 * It frees CPU workarea, releases the DMA and uninitializes the SGI.
 *
 * @param      session          Handle for the current CL session.
 * @param      pContext         Pointer to multipart context
 * @param      key              Handle for the key
 * @param[in]  cpuWaSizeInWords Number of cpu wa words to free
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_cleanupOnExit_dmaDriven)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_cleanupOnExit_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_Context_t *pContext,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords);




#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMACMODES_SGI_CLEANUP_H_ */
