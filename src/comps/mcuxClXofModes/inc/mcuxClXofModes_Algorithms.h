/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

/** @file  mcuxClXof_Algorithms.h
 *  @brief Algorithm/mode definitions for the mcuxClXofModes component
 */

#ifndef MCUXCLXOFMODES_ALGORITHMS_H_
#define MCUXCLXOFMODES_ALGORITHMS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClXof_Types.h>
#include <mcuxClHash_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* @defgroup mcuxClXofModes_Algorithms mcuxClXofModes_Algorithms
* @brief Xof algorithms of the @ref mcuxClXofModes component
* @ingroup mcuxClXofModes
* @{
*/

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Declaration provided for externally accessible API")
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()





#ifdef MCUXCL_FEATURE_XOF_C_SHAKE_128
/**
 * @brief SHAKE-128 algorithm descriptor
 *        SHAKE-128 Xof calculation using an underlying software implementation of Keccak.
 */
extern const mcuxClXof_AlgorithmDescriptor_t mcuxClXof_AlgorithmDescriptor_C_Shake_128;

/**
 * @brief SHAKE-128 algorithm descriptor
 *        SHAKE-128 Xof calculation using an underlying software implementation of Keccak.
 * \implements{REQ_788292}
 */
static mcuxClXof_Algo_t mcuxClXof_Algorithm_Shake_128 = &mcuxClXof_AlgorithmDescriptor_C_Shake_128;
#endif /* MCUXCL_FEATURE_XOF_C_SHAKE_128 */

#ifdef MCUXCL_FEATURE_XOF_C_SHAKE_256
/**
 * @brief SHAKE-256 algorithm descriptor
 *        SHAKE-256 Xof calculation using an underlying software implementation of Keccak.
 */
extern const mcuxClXof_AlgorithmDescriptor_t mcuxClXof_AlgorithmDescriptor_C_Shake_256;

/**
 * @brief SHAKE-256 algorithm descriptor
 *        SHAKE-256 Xof calculation using an underlying software implementation of Keccak.
 * \implements{REQ_788292}
 */
static mcuxClXof_Algo_t mcuxClXof_Algorithm_Shake_256 = &mcuxClXof_AlgorithmDescriptor_C_Shake_256;
#endif /* MCUXCL_FEATURE_XOF_C_SHAKE_256 */



MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()

/**@}*/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLXOFMODES_ALGORITHMS_H_ */
