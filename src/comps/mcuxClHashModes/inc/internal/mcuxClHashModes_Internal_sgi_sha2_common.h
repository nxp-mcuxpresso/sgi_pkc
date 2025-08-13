/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

/** @file  mcuxClHashModes_Internal_sgi_sha2_common.h
 *  @brief Internal declarations descriptors for the SGI SHA2
 */

#ifndef MCUXCLHASHMODES_INTERNAL_SGI_SHA2_COMMON_H_
#define MCUXCLHASHMODES_INTERNAL_SGI_SHA2_COMMON_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClHash_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************
 * Algorithm descriptor implementations
 **********************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/**
 * @brief Sha2-224 algorithm descriptor
 *        Sha2-224 hash calculation using the Hash functionality SGI.
 */
extern const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha224;

/**
 * @brief Sha2-256 algorithm descriptor
 *        Sha2-256 hash calculation using the Hash functionality SGI.
 */
extern const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha256;

/**
 * @brief Sha2-384 algorithm descriptor
 *        Sha2-384 hash calculation using the Hash functionality SGI.
 */
extern const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha384;

/**
 * @brief Sha2-512 algorithm descriptor
 *        Sha2-512 hash calculation using the Hash functionality SGI.
 */
extern const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha512;


MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLHASHMODES_INTERNAL_SGI_SHA2_COMMON_H_ */
