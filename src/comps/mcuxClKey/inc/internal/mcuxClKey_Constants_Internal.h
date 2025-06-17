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
 * @file  mcuxClKey_Constants_Internal.h
 * @brief Provide constants of the internal mcuxClKey component.
 */

#ifndef MCUXCLKEY_CONSTANTS_INTERNAL_H_
#define MCUXCLKEY_CONSTANTS_INTERNAL_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClKey_Types.h>
#include <mcuxCsslAnalysis.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * CONSTANTS
 **********************************************/

#define MCUXCLKEY_CRC16_SEED   (0xFFFFu)       ///< The initial seed of the default 16-bit CRC algorithm

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKEY_CONSTANTS_INTERNAL_H_ */

