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

/** @file  mcuxClCipherModes_Modes.h
 *  @brief Supported modes for the mcuxClCipher component
 */

#ifndef MCUXCLCIPHERMODES_MODES_H_
#define MCUXCLCIPHERMODES_MODES_H_

#include <mcuxClCipher_Types.h>

#include <mcuxCsslAnalysis.h>

#include <mcuxClConfig.h> // Exported features flags header

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClCipherModes_Modes mcuxClCipherModes_Modes
 * @brief Modes used by the Cipher operations.
 * @ingroup mcuxClCipherModes
 * @{
 */

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Consumed by user / customer. Hence, it is declared but never referenced. ")

/**
 * @brief AES-ECB mode descriptor without padding
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_NoPadding;

/**
 * @brief AES-ECB mode without padding.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_ECB_NoPadding.
 * \implements{REQ_788210,REQ_788217}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_ECB_NoPadding =
  &mcuxClCipher_ModeDescriptor_AES_ECB_NoPadding;

/**
 * @brief AES-ECB mode descriptor with ISO/IEC 9797-1 padding method 1
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method1;

/**
 * @brief AES-ECB mode with ISO/IEC 9797-1 padding method 1.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method1.
 *
 * \implements{REQ_788210,REQ_788217,REQ_788211}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_ECB_PaddingISO9797_1_Method1 =
  &mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method1;

/**
 * @brief AES-ECB mode descriptor with ISO/IEC 9797-1 padding method 2
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method2;

/**
 * @brief AES-ECB mode with ISO/IEC 9797-1 padding method 2.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method2.
 *
 * \implements{REQ_788210,REQ_788217,REQ_788212}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_ECB_PaddingISO9797_1_Method2 =
  &mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method2;

/**
 * @brief AES-ECB mode descriptor with PKCS#7 padding
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingPKCS7;

/**
 * @brief AES-ECB mode with PKCS#7 padding.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_ECB_PaddingPKCS7.
 *
 * \implements{REQ_788210,REQ_788217,REQ_788213}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_ECB_PaddingPKCS7 =
  &mcuxClCipher_ModeDescriptor_AES_ECB_PaddingPKCS7;

/**
 * @brief AES-ECB mode descriptor without padding, non-blocking API, using the DMA for I/O operations.
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_NoPadding_NonBlocking;

/**
 * @brief AES-ECB mode without padding, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_ECB_NoPadding_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550251}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_ECB_NoPadding_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_ECB_NoPadding_NonBlocking;

/**
 * @brief AES-ECB mode descriptor with ISO/IEC 9797-1 padding method 1, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method1_NonBlocking;

/**
 * @brief AES-ECB mode with ISO/IEC 9797-1 padding method 1, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method1_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550251,REQ_788211}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_ECB_PaddingISO9797_1_Method1_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method1_NonBlocking;

/**
 * @brief AES-ECB mode descriptor with ISO/IEC 9797-1 padding method 2, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method2_NonBlocking;

/**
 * @brief AES-ECB mode with ISO/IEC 9797-1 padding method 2, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method2_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550251,REQ_788212}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_ECB_PaddingISO9797_1_Method2_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_ECB_PaddingISO9797_1_Method2_NonBlocking;

/**
 * @brief AES-ECB mode descriptor with PKCS#7 padding, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_ECB_PaddingPKCS7_NonBlocking;

/**
 * @brief AES-ECB mode with PKCS#7 padding, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_ECB_PaddingPKCS7_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550251,REQ_788213}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_ECB_PaddingPKCS7_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_ECB_PaddingPKCS7_NonBlocking;

/**
 * @brief AES-CBC mode descriptor without padding
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_NoPadding;

/**
 * @brief AES-CBC mode without padding.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CBC_NoPadding.
 *
 * \implements{REQ_788210,REQ_788219}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CBC_NoPadding =
  &mcuxClCipher_ModeDescriptor_AES_CBC_NoPadding;

/**
 * @brief AES-CBC mode descriptor with ISO/IEC 9797-1 padding method 1
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method1;

/**
 * @brief AES-CBC mode with ISO/IEC 9797-1 padding method 1.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method1.
 *
 * \implements{REQ_788210,REQ_788219,REQ_788211}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CBC_PaddingISO9797_1_Method1 =
  &mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method1;

/**
 * @brief AES-CBC mode descriptor with ISO/IEC 9797-1 padding method 2
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method2;

/**
 * @brief AES-CBC mode with ISO/IEC 9797-1 padding method 2.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method2.
 *
 * \implements{REQ_788210,REQ_788219,REQ_788212}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CBC_PaddingISO9797_1_Method2 =
  &mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method2;

/**
 * @brief AES-CBC mode descriptor with PKCS#7 padding
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingPKCS7;

/**
 * @brief AES-CBC mode with PKCS#7 padding.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CBC_PaddingPKCS7.
 *
 * \implements{REQ_788210,REQ_788219,REQ_788213}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CBC_PaddingPKCS7 =
  &mcuxClCipher_ModeDescriptor_AES_CBC_PaddingPKCS7;

/**
 * @brief AES-CBC mode descriptor without padding, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_NoPadding_NonBlocking;

/**
 * @brief AES-CBC mode without padding, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CBC_NoPadding_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550252}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CBC_NoPadding_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_CBC_NoPadding_NonBlocking;

/**
 * @brief AES-CBC mode descriptor with ISO/IEC 9797-1 padding method 1, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method1_NonBlocking;

/**
 * @brief AES-CBC mode with ISO/IEC 9797-1 padding method 1, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method1_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550252,REQ_788211}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CBC_PaddingISO9797_1_Method1_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method1_NonBlocking;

/**
 * @brief AES-CBC mode descriptor with ISO/IEC 9797-1 padding method 2, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method2_NonBlocking;

/**
 * @brief AES-CBC mode with ISO/IEC 9797-1 padding method 2, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method2_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550252,REQ_788212}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CBC_PaddingISO9797_1_Method2_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_CBC_PaddingISO9797_1_Method2_NonBlocking;

/**
 * @brief AES-CBC mode descriptor with PKCS#7 padding, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CBC_PaddingPKCS7_NonBlocking;

/**
 * @brief AES-CBC mode with PKCS#7 padding, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CBC_PaddingPKCS7_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550252,REQ_788213}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CBC_PaddingPKCS7_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_CBC_PaddingPKCS7_NonBlocking;

/**
 * @brief AES-CTR mode descriptor
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CTR;

/**
 * @brief AES-CTR mode.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CTR.
 *
 * \implements{REQ_788210,REQ_788223}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CTR =
  &mcuxClCipher_ModeDescriptor_AES_CTR;

/**
 * @brief AES-CTR mode descriptor, non-blocking API, using the DMA for I/O operations
 * @note Interrupts must be enabled on both involved DMA channels with properly installed handlers.
 * If the non-blocking Cipher operation returns @ref MCUXCLCIPHER_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * @attention The input length for this mode has an upper limit of 0x7fff0 bytes per API call.
 * Bigger sizes need to be split into multiple process calls.
 *
 */
extern const mcuxClCipher_ModeDescriptor_t mcuxClCipher_ModeDescriptor_AES_CTR_NonBlocking;

/**
 * @brief AES-CTR mode, non-blocking API, using the DMA for I/O operations.
 *
 * See @ref mcuxClCipher_ModeDescriptor_AES_CTR_NonBlocking.
 *
 * \implements{REQ_788210,REQ_1550253}
 */
static mcuxClCipher_Mode_t mcuxClCipher_Mode_AES_CTR_NonBlocking =
  &mcuxClCipher_ModeDescriptor_AES_CTR_NonBlocking;


MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLCIPHERMODES_MODES_H_ */

