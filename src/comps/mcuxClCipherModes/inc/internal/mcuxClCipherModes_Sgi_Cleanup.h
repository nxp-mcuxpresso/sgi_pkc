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

#ifndef MCUXCLCIPHERMODES_SGI_CLEANUP_H_
#define MCUXCLCIPHERMODES_SGI_CLEANUP_H_

#include <mcuxClSession_Types.h>
#include <mcuxClSgi_Types.h>

#include <mcuxClAes.h>
#include <mcuxClBuffer.h>
#include <mcuxClKey.h>
#include <mcuxClMemory_Copy.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClCipherModes_Sgi_Functions.h>

/* Defines to control HW cleanup in cleanupOnExit functions. */
#define MCUXCLCIPHERMODES_CLEANUP_HW_ALL     0x00000F0Fu
#define MCUXCLCIPHERMODES_CLEANUP_HW_SGI     0x0000000Fu
#define MCUXCLCIPHERMODES_CLEANUP_HW_DMA     0x00000F00u
#define MCUXCLCIPHERMODES_CLEANUP_HW_NONE    0xFFFF0000u

/**
 * @brief Function to handle OK and ERROR/FAILURE exit
 *
 * Use this function to leave functions in this file in _not_ FAULT_ATTACK cases.
 * It frees CPU workarea and uninitializes the SGI.
 *
 * @param      session          Handle for the current CL session.
 * @param      pContext         Pointer to multipart context
 * @param      key              Handle for the key.
 *                              If the key is in the context, this param shall be NULL.
 * @param[in]  cpuWaSizeInWords Number of cpu wa words to free
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_cleanupOnExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_cleanupOnExit(
    mcuxClSession_Handle_t session,
    mcuxClCipherModes_Context_Aes_Sgi_t *pContext,
    mcuxClKey_Handle_t key,
    uint32_t cpuWaSizeInWords
);

/**
 * @brief Function to handle OK and ERROR/FAILURE exit
 *
 * Use this function to leave functions in this file in _not_ FAULT_ATTACK cases.
 * It frees CPU workarea, releases the DMA and uninitializes the SGI.
 *
 * @param      session          Handle for the current CL session.
 * @param      pContext         Pointer to multipart context
 * @param      key              Handle for the used key
 * @param[in]  cpuWaSizeInWords Number of cpu wa words to free
 * @param[in]  cleanupDmaSgi    Instructions on whether to clean DMA, SGI,
 *                               can be either of these values:
 *                                 #MCUXCLCIPHERMODES_CLEANUP_HW_ALL
 *                                 #MCUXCLCIPHERMODES_CLEANUP_HW_SGI
 *                                 #MCUXCLCIPHERMODES_CLEANUP_HW_DMA
 *                                 #MCUXCLCIPHERMODES_CLEANUP_HW_NONE
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_cleanupOnExit_dmaDriven)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_cleanupOnExit_dmaDriven(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_Context_Aes_Sgi_t *pContext,
  mcuxClKey_Handle_t key,
  uint32_t cpuWaSizeInWords,
  uint32_t cleanupDmaSgi
);

/**
 * @brief Function to handle DMA errors that occurred during SGI AUTO mode with handshakes.
 *
 * This function cleans up the SGI in case an error happened during/after AUTO mode
 * with DMA handshakes.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_handleDmaError_autoModeNonBlocking)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_handleDmaError_autoModeNonBlocking(void);

#endif /* MCUXCLCIPHERMODES_SGI_CLEANUP_H_ */
