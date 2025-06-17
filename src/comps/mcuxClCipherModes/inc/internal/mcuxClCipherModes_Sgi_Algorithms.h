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

/** @file  mcuxClCipherModes_Sgi_Algorithms.h
 *  @brief Supported algorithms for the mcuxClCipherModes component
 */

#ifndef MCUXCLCIPHERMODES_SGI_ALGORITHMS_H_
#define MCUXCLCIPHERMODES_SGI_ALGORITHMS_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <internal/mcuxClCipherModes_Sgi_Types.h>
#include <internal/mcuxClCipherModes_Common_Constants.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @defgroup clCipherModesAlgorithms Cipher algorithm definitions
 * @brief Modes used by the Cipher operations.
 * @ingroup mcuxClCipherModes
 * @{
 */

/**
 * @brief ECB algorithm descriptor without padding, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_NoPadding_Sgi;

/**
 * @brief ECB algorithm descriptor with ISO/IEC 9797-1 padding method 1, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method1_Sgi;

/**
 * @brief ECB algorithm descriptor with ISO/IEC 9797-1 padding method 2, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method2_Sgi;

/**
 * @brief ECB algorithm descriptor with PKCS#7 padding, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingPKCS7_Sgi;


/**
 * @brief Blocking ECB algorithm descriptor for non-blocking operations, using SGI, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_NoPadding_Sgi_NonBlocking;

/**
 * @brief Blocking ECB algorithm descriptor with ISO/IEC 9797-1 padding method 1 for non-blocking operations, using SGI, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method1_Sgi_NonBlocking;

/**
 * @brief Blocking ECB algorithm descriptor with ISO/IEC 9797-1 padding method 2 for non-blocking operations, using SGI, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingISO9797_1_Method2_Sgi_NonBlocking;

/**
 * @brief Blocking ECB algorithm descriptor with PKCS#7 padding for non-blocking operations, using SGI, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_ECB_PaddingPKCS7_Sgi_NonBlocking;


/**
 * @brief CBC algorithm descriptor without padding, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_NoPadding_Sgi;

/**
 * @brief CBC algorithm descriptor with ISO/IEC 9797-1 padding method 1, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method1_Sgi;

/**
 * @brief CBC algorithm descriptor with ISO/IEC 9797-1 padding method 2, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method2_Sgi;

/**
 * @brief CBC algorithm descriptor with PKCS#7 padding, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingPKCS7_Sgi;


/**
 * @brief Non blocking CBC algorithm descriptor for non-blocking operations, using SGI, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_NoPadding_Sgi_NonBlocking;

/**
 * @brief Non blocking CBC algorithm descriptor with ISO/IEC 9797-1 padding method 1 for non-blocking operations, using SGI, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method1_Sgi_NonBlocking;

/**
 * @brief Non blocking CBC algorithm descriptor with ISO/IEC 9797-1 padding method 2 for non-blocking operations, using SGI, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingISO9797_1_Method2_Sgi_NonBlocking;

/**
 * @brief Non blocking CBC algorithm descriptor with PKCS#7 padding for non-blocking operations, using SGI, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CBC_PaddingPKCS7_Sgi_NonBlocking;


/**
 * @brief CTR algorithm descriptor, using SGI
 *
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CTR_Sgi;

/**
 * @brief CTR algorithm descriptor, using SGI, for non-blocking operations, performing I/O operations with the DMA
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi_t mcuxClCipherModes_AlgorithmDescriptor_CTR_Sgi_NonBlocking;






/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLCIPHERMODES_SGI_ALGORITHMS_H_ */
