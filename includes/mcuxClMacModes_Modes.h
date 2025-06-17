/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

#ifndef MCUXCLMACMODES_MODES_H_
#define MCUXCLMACMODES_MODES_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClMac_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClMacModes_Modes mcuxClMacModes_Modes
 * @brief Modes used by the MAC operations.
 * @ingroup mcuxClMacModes
 * @{
 */

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Declaration provided for externally accessible API")


/**
 * @brief AES-CMAC mode descriptor
 */
extern const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CMAC;

/**
 * @brief AES-CMAC mode.
 *
 * See @ref mcuxClMac_ModeDescriptor_CMAC.
 *
 * \implements{REQ_788232,REQ_788235}
 */
static mcuxClMac_Mode_t mcuxClMac_Mode_CMAC =
  &mcuxClMac_ModeDescriptor_CMAC;


/**
 * @brief AES-CMAC mode descriptor, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on the DMA input channel with a properly installed handler.
 * If the non-blocking Mac operation returns @ref MCUXCLMAC_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CMAC_NonBlocking;

/**
 * @brief AES-CMAC mode, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClMac_ModeDescriptor_CMAC_NonBlocking.
 *
 * \implements{REQ_1550258,REQ_788235}
 */
static mcuxClMac_Mode_t mcuxClMac_Mode_CMAC_NonBlocking =
  &mcuxClMac_ModeDescriptor_CMAC_NonBlocking;




/**
 * @brief AES-CBC-MAC mode descriptor with ISO/IEC 9797-1 padding method 1
 */
extern const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method1;

/**
 * @brief AES-CBC-MAC mode with ISO/IEC 9797-1 padding method 1.
 *
 * See @ref mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method1.
 *
 * \implements{REQ_788237}
 */
static mcuxClMac_Mode_t mcuxClMac_Mode_CBCMAC_PaddingISO9797_1_Method1 =
  &mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method1;


MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMACMODES_MODES_H_ */
