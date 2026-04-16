/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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

/** @file  mcuxClXof_Types.h
 *  @brief Type definitions for the mcuxClXof component
 */

#ifndef MCUXCLXOF_TYPES_H_
#define MCUXCLXOF_TYPES_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClXof_Types mcuxClXof_Types
 * @brief Types used by the XOF operations.
 * @ingroup mcuxClXof
 * @{
 */

/**
 * @brief XOF mode/algorithm descriptor type
 *
 * This type captures all the information that the XOF interfaces need to
 * know about a particular Hash mode/algorithm.
 *
 */
typedef struct mcuxClXof_AlgorithmDescriptor mcuxClXof_AlgorithmDescriptor_t;

/**
 * @brief XOF mode/algorithm type
 *
 * This type is used to refer to a XOF mode/algorithm.
 *
 */
typedef const mcuxClXof_AlgorithmDescriptor_t * const mcuxClXof_Algo_t;

/**
 * \brief XOF context structure
 *
 * This structure is used in the multi-part interfaces to store the
 * information about the current operation and the relevant internal state.
 */
typedef struct mcuxClXof_ContextDescriptor mcuxClXof_ContextDescriptor_t;

/**
 * \brief XOF context type
 *
 * This type is used in the multi-part interfaces to store the information
 * about the current operation and the relevant internal state.
 */
typedef mcuxClXof_ContextDescriptor_t * const mcuxClXof_Context_t;

/**
 * \brief XOF status code
 *
 * This type provides information about the status of the XOF operation that
 * has been performed.
 */
typedef uint32_t mcuxClXof_Status_t;

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLXOF_TYPES_H_ */
