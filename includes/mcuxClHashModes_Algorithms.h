/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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

/** @file  mcuxClHashModes_Algorithms.h
 *  @brief Algorithm/mode definitions for the mcuxClHashModes component
 */

#ifndef MCUXCLHASHMODES_ALGORITHMS_H_
#define MCUXCLHASHMODES_ALGORITHMS_H_

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
* @ingroup mcuxClHashModes
* @{
*/

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Declaration provided for externally accessible API")
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()









/**
 * @brief Sha-224 algorithm descriptor
 *        Sha-224 hash calculation using the Hash functionality SGI.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sgi_Sha224;

/**
 * @brief Sha-224 algorithm descriptor
 *        Sha-224 hash calculation using the Hash functionality SGI.
 * \implements{REQ_788287}
 */
static mcuxClHash_Algo_t mcuxClHash_Algorithm_Sha224 = &mcuxClHash_AlgorithmDescriptor_Sgi_Sha224;

/**
 * @brief Sha-224 algorithm descriptor
 *        Sha-224 hash calculation using the Hash non-blocking functionality SGI.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sgi_Sha224_Dma_NonBlocking;

/**
 * @brief Sha-224 algorithm descriptor
 *        Sha-224 hash calculation using the Hash non-blocking functionality SGI.
 * @note Interrupts must be enabled on the DMA input channel with a properly installed handler.
 * If the non-blocking Hash operation returns @ref MCUXCLHASH_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * \implements{REQ_1550262}
 */
static mcuxClHash_Algo_t mcuxClHash_Algorithm_Sha224_Dma_NonBlocking = &mcuxClHash_AlgorithmDescriptor_Sgi_Sha224_Dma_NonBlocking;


/**
 * @brief Sha-256 algorithm descriptor
 *        Sha-256 hash calculation using the Hash functionality SGI.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sgi_Sha256;

/**
 * @brief Sha-256 algorithm descriptor
 *        Sha-256 hash calculation using the Hash functionality SGI.
 * \implements{REQ_788287}
 */
static mcuxClHash_Algo_t mcuxClHash_Algorithm_Sha256 = &mcuxClHash_AlgorithmDescriptor_Sgi_Sha256;
/**
 * @brief Sha-256 algorithm descriptor
 *        Sha-256 hash calculation using the Hash non-blocking functionality SGI.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sgi_Sha256_Dma_NonBlocking;

/**
 * @brief Sha-256 algorithm descriptor
 *        Sha-256 hash calculation using the Hash non-blocking functionality SGI.
 * @note Interrupts must be enabled on the DMA input channel with a properly installed handler.
 * If the non-blocking Hash operation returns @ref MCUXCLHASH_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * \implements{REQ_1550262}
 */
static mcuxClHash_Algo_t mcuxClHash_Algorithm_Sha256_Dma_NonBlocking = &mcuxClHash_AlgorithmDescriptor_Sgi_Sha256_Dma_NonBlocking;

/**
 * @brief Sha-384 algorithm descriptor
 *        Sha-384 hash calculation using the Hash functionality SGI.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sgi_Sha384;

/**
 * @brief Sha-384 algorithm descriptor
 *        Sha-384 hash calculation using the Hash functionality SGI.
 * @note Interrupts must be enabled on the DMA input channel with a properly installed handler.
 * If the non-blocking Hash operation returns @ref MCUXCLHASH_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * \implements{REQ_788288}
 */
static mcuxClHash_Algo_t mcuxClHash_Algorithm_Sha384 = &mcuxClHash_AlgorithmDescriptor_Sgi_Sha384;
/**
 * @brief Sha-384 algorithm descriptor
 *        Sha-384 hash calculation using the Hash non-blocking functionality SGI.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sgi_Sha384_Dma_NonBlocking;

/**
 * @brief Sha-384 algorithm descriptor
 *        Sha-384 hash calculation using the Hash non-blocking functionality SGI.
 * @note Interrupts must be enabled on the DMA input channel with a properly installed handler.
 * If the non-blocking Hash operation returns @ref MCUXCLHASH_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * \implements{REQ_1550264}
 */
static mcuxClHash_Algo_t mcuxClHash_Algorithm_Sha384_Dma_NonBlocking = &mcuxClHash_AlgorithmDescriptor_Sgi_Sha384_Dma_NonBlocking;

/**
 * @brief Sha-512 algorithm descriptor
 *        Sha-512 hash calculation using the Hash functionality SGI.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sgi_Sha512;

/**
 * @brief Sha-512 algorithm descriptor
 *        Sha-512 hash calculation using the Hash functionality SGI.
 * @note Interrupts must be enabled on the DMA input channel with a properly installed handler.
 * If the non-blocking Hash operation returns @ref MCUXCLHASH_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * \implements{REQ_788288}
 */
#define mcuxClHash_Algorithm_Sha512 (&mcuxClHash_AlgorithmDescriptor_Sgi_Sha512)
/**
 * @brief Sha-512 algorithm descriptor
 *        Sha-512 hash calculation using the Hash non-blocking functionality SGI.
 */
extern const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sgi_Sha512_Dma_NonBlocking;

/**
 * @brief Sha-512 algorithm descriptor
 *        Sha-512 hash calculation using the Hash non-blocking functionality SGI.
 * @note Interrupts must be enabled on the DMA input channel with a properly installed handler.
 * If the non-blocking Hash operation returns @ref MCUXCLHASH_STATUS_JOB_STARTED, a
 * non-blocking operation has started and the CPU is unblocked in the meantime.
 *
 * \implements{REQ_1550264}
 */
static mcuxClHash_Algo_t mcuxClHash_Algorithm_Sha512_Dma_NonBlocking = &mcuxClHash_AlgorithmDescriptor_Sgi_Sha512_Dma_NonBlocking;















MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()

/**@}*/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLHASHMODES_ALGORITHMS_H_ */
