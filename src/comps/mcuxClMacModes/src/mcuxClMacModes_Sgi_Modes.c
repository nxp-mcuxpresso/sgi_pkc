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

/** @file  mcuxClMacModes_Sgi_Modes.c
 *  @brief Definition of the SGI mode descriptors for all provided MAC modes
 */

#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClMac_Types.h>
#include <mcuxClMacModes_Constants.h>
#include <mcuxClMacModes_MemoryConsumption.h>
#include <mcuxClMacModes_Modes.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClMacModes_Sgi_Algorithms.h>
#include <internal/mcuxClMacModes_Common_Functions.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClMacModes_Sgi_Cbcmac.h>
#include <internal/mcuxClMacModes_Sgi_Gmac.h>

/**
 *  Constant top-level mode descriptors and common mode descriptors for custom modes
 */

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the generic structure member.")

/**
 *  Top-level mode structure for CMAC
 */
const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CMAC = {
  .common = {
    .compute = mcuxClMacModes_compute,
    .protectionToken_compute = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_compute),
    .init = mcuxClMacModes_init,
    .protectionToken_init = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_init),
    .process = mcuxClMacModes_process,
    .protectionToken_process = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_process),
    .finish = mcuxClMacModes_finish,
    .protectionToken_finish = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finish),
    .macByteSize = MCUXCLMAC_CMAC_OUTPUT_SIZE,
    .pAlgorithm = (void *) &mcuxClMacModes_AlgorithmDescriptor_CMAC
  },
  .pCustom = NULL
};


/**
 *  Top-level mode structure for CMAC in non-blocking mode
 */
const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CMAC_NonBlocking = {
  .common = {
    .compute = mcuxClMacModes_compute_dmaDriven,
    .protectionToken_compute = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_compute_dmaDriven),
    .init = mcuxClMacModes_init,
    .protectionToken_init = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_init),
    .process = mcuxClMacModes_process_dmaDriven,
    .protectionToken_process = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_process_dmaDriven),
    .finish = mcuxClMacModes_finish,
    .protectionToken_finish = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finish),
    .macByteSize = MCUXCLMAC_CMAC_OUTPUT_SIZE,

    .pAlgorithm = (void *) &mcuxClMacModes_AlgorithmDescriptor_CMAC_NonBlocking
  },
  .pCustom = NULL
};





/**
 *  Top-level mode structure for CBCMAC using ISO9797-1 Method 1 Padding
 *  This mode is used by CBCMAC and AeadModes-CCM
 */
const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method1 = {
  .common = {
    .compute = mcuxClMacModes_compute,
    .protectionToken_compute = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_compute),
    .init = mcuxClMacModes_init,
    .protectionToken_init = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_init),
    .process = mcuxClMacModes_process,
    .protectionToken_process = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_process),
    .finish = mcuxClMacModes_finish,
    .protectionToken_finish = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finish),
    .macByteSize = MCUXCLMAC_CBCMAC_OUTPUT_SIZE,
    .pAlgorithm = (void *) &mcuxClMacModes_AlgorithmDescriptor_CBCMAC_PaddingISO9797_1_Method1
  },
  .pCustom = NULL
};

/**
 *  Common mode structure for GMAC
 */
const mcuxClMac_CommonModeDescriptor_t mcuxClMac_CommonModeDescriptor_GMAC = {
  .compute = mcuxClMacModes_compute,
  .protectionToken_compute = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_compute),
  .init = mcuxClMacModes_init,
  .protectionToken_init = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_init),
  .process = mcuxClMacModes_process,
  .protectionToken_process = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_process),
  .finish = mcuxClMacModes_finish,
  .protectionToken_finish = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finish),
  .macByteSize = MCUXCLMAC_GMAC_OUTPUT_SIZE,

  .pAlgorithm = (void *) &mcuxClMacModes_AlgorithmDescriptor_GMAC
};

/**
 *  Note: We do not provide a top-level mode structure for GMAC, as the caller
 *  needs to call the function @ref mcuxClMacModes_createGmacMode to construct it.
 */

MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
