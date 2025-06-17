/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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

/**
 * @file  mcuxClKey_Internal_EncodingMechanisms.h
 * @brief Provide API of the internal mcuxClKey_Encoding functions
 */

#ifndef MCUXCLKEY_INTERNAL_ENCODINGMECHANISMS_H_
#define MCUXCLKEY_INTERNAL_ENCODINGMECHANISMS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClKey_Types.h>
#include <mcuxCsslAnalysis.h>

#ifdef __cplusplus
extern "C" {
#endif

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Consumed by user / customer. Hence, it is declared but never referenced. ")

/**
 * @defgroup mcuxClKey_Internal_EncodingMechanisms mcuxClKey_Internal_EncodingMechanisms
 * @brief Internal mechanisms used by the Key operations.
 * @ingroup mcuxClKey
 * @{
 */

/**
 * @brief Key encoding descriptor for loading a plain key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClKey_EncodingDescriptor_Plain;
/**
 * @brief Key encoding for loading a plain key.
 */
static const mcuxClKey_Encoding_t mcuxClKey_Encoding_Plain = &mcuxClKey_EncodingDescriptor_Plain;

/** @} */

MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKEY_INTERNAL_ENCODINGMECHANISMS_H_ */

