/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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

/** @file  mcuxClMacModes_Sgi_Algorithms.h
 *  @brief Internal header for the MAC context for modes using the SGI
 */

#ifndef MCUXCLMACMODES_SGI_ALGORITHMS_H_
#define MCUXCLMACMODES_SGI_ALGORITHMS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClMac_Types.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClMacModes_Common_Constants.h>
#include <internal/mcuxClMacModes_Sgi_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  CMAC algorithm descriptors using SGI
 */
extern const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_CMAC;
extern const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_CMAC_NonBlocking;


/**
 *  CBC-MAC algorithm descriptors using SGI
 */

extern const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_CBCMAC_PaddingISO9797_1_Method1; // this descriptor is also needed by AeadModes-CCM

/**
 *  GMAC algorithm descriptors using SGI
 */
extern const mcuxClMac_CommonModeDescriptor_t mcuxClMac_CommonModeDescriptor_GMAC; /* needed for constructor of GMAC mode */
extern const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_GMAC;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMACMODES_SGI_ALGORITHMS_H_ */
