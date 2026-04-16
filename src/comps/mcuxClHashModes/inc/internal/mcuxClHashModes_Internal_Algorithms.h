/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/** @file  mcuxClHashModes_Internal_Algorithms.h
 *  @brief Algorithm/mode definitions for the mcuxClHashModes component used internally
 */

#ifndef MCUXCLHASHMODES_INTERNAL_ALGORITHMS_H_
#define MCUXCLHASHMODES_INTERNAL_ALGORITHMS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClHash_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* @defgroup mcuxClHashModes_Algorithms mcuxClHashModes_Algorithms
* @brief Hashing algorithms of the @ref mcuxClHashModes component
* @ingroup mcuxClHash_Constants
* @{
*/

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Declaration provided for externally accessible API")
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()





#ifdef MCUXCL_FEATURE_HASH_C_SHA3_SHAKE
/**
 * @brief Sha3-shake-128 algorithm descriptor
 *        Sha3-shake-128 hash calculation using an underlying software implementation of Keccak.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_C_Sha3_Shake_128;

/**
 * @brief Sha3-shake-128 algorithm descriptor
 *        Sha3-shake-128 hash calculation using an underlying software implementation of Keccak.
 */
static mcuxClHash_Algo_t mcuxClHash_Algorithm_Sha3_Shake_128 = &mcuxClHash_AlgorithmDescriptor_C_Sha3_Shake_128;


/**
 * @brief Sha3-shake-256 algorithm descriptor
 *        Sha3-shake-256 hash calculation using an underlying software implementation of Keccak.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_C_Sha3_Shake_256;

/**
 * @brief Sha3-shake-256 algorithm descriptor
 *        Sha3-shake-256 hash calculation using an underlying software implementation of Keccak.
 */
#define mcuxClHash_Algorithm_Sha3_Shake_256 (&mcuxClHash_AlgorithmDescriptor_C_Sha3_Shake_256)
#endif /* MCUXCL_FEATURE_HASH_C_SHA3_SHAKE */


MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()

/**@}*/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLHASHMODES_INTERNAL_ALGORITHMS_H_ */
