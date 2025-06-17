/*--------------------------------------------------------------------------*/
/* Copyright 2020-2024 NXP                                                  */
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

/** @file  mcuxClAeadModes_Modes.h
 *  @brief This file defines the modes for the mcuxClAeadModes component */

#ifndef MCUXCLAEADMODES_MODES_H_
#define MCUXCLAEADMODES_MODES_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClAead_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClAeadModes_Modes mcuxClAeadModes_Modes
 * @brief Modes used by the AEAD operations.
 * @ingroup mcuxClAeadModes
 * @{
 */

MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_API_DECLARATIONS()

/**
 * @brief AES-CCM mode descriptor
 */
extern const mcuxClAead_ModeDescriptor_t mcuxClAead_ModeDescriptor_AES_CCM;

/**
 * @brief AES-CCM mode.
 *
 * See @ref mcuxClAead_ModeDescriptor_AES_CCM.
 *
 * \implements{REQ_788225}
 */
static mcuxClAead_Mode_t mcuxClAead_Mode_CCM =
  &mcuxClAead_ModeDescriptor_AES_CCM;

/**
 * @brief GCM mode descriptor
 */
extern const mcuxClAead_ModeDescriptor_t mcuxClAead_ModeDescriptor_AES_GCM;

/**
 * @brief GCM mode.
 *
 * See @ref mcuxClAead_ModeDescriptor_AES_GCM.
 * 
 * \implements{REQ_788227}
 */
static mcuxClAead_Mode_t mcuxClAead_Mode_GCM =
  &mcuxClAead_ModeDescriptor_AES_GCM;


MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_API_DECLARATIONS()

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAEADMODES_MODES_H_ */
