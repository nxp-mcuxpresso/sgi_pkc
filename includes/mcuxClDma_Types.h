/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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
 * @file  mcuxClDma_Types.h
 * @brief Type and associated constant definitions of the mcuxClDma component.
 */

#ifndef MCUXCLDMA_TYPES_H_
#define MCUXCLDMA_TYPES_H_

#include <mcuxClCore_Platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClDma mcuxClDma
 * @brief DMA component
 * 
 * @defgroup mcuxClDma_Types mcuxClDma_Types
 * @brief Defines the types and associated constants of the @ref mcuxClDma component.
 * @ingroup mcuxClDma
 * @{
 */

/**
 * @brief DMA status code
 *
 * This type provides information about the status of the DMA operation that
 * has been performed.
 */
typedef uint32_t mcuxClDma_Status_t;

/* Status/error codes */
#define MCUXCLDMA_STATUS_SOURCE_BUS_ERROR        ((mcuxClDma_Status_t) 0x03335330u) ///< Source address bus is not accessible by DMA
#define MCUXCLDMA_STATUS_DESTINATION_BUS_ERROR   ((mcuxClDma_Status_t) 0x03335334u) ///< Destination address bus is not accessible by DMA
#define MCUXCLDMA_STATUS_CONFIGURATION_ERROR     ((mcuxClDma_Status_t) 0x03335338u) ///< DMA was not correctly configured
#define MCUXCLDMA_STATUS_OK                      ((mcuxClDma_Status_t) 0x03332E03u) ///< No error occurred

/**
 * @}
 */ /* mcuxClDma_Types */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLDMA_TYPES_H_ */
