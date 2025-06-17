/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023, 2025 NXP                                            */
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
 * @file  mcuxClResource_Types.h
 * @brief Type definitions for the mcuxClResource component
 */


#ifndef MCUXCLRESOURCE_TYPES_H_
#define MCUXCLRESOURCE_TYPES_H_

#include <mcuxClCore_Platform.h>


/**********************************************
 * TYPEDEFS
 **********************************************/
/**
 * @defgroup mcuxClResource_Types mcuxClResource_Types
 * @brief Defines all types of @ref mcuxClResource
 * @ingroup mcuxClResource
 * @{
 */

/**
 * @brief Type for mcuxClResource status codes
 *
 * This type provides information about the status of the Resource operation
 * that has been performed.
 */
typedef uint32_t mcuxClResource_Status_t;

/**
 * @brief Resource context type
 */
typedef struct mcuxClResource_Context mcuxClResource_Context_t;

/**
 * @brief Callback type for acquiring a mutex
 */
typedef uint32_t (*mcuxClResource_MutexAcquire_Callback_t)(uint32_t value);

/**
 * @brief Callback type for releasing a mutex
 */
typedef uint32_t (*mcuxClResource_MutexRelease_Callback_t)(uint32_t value);

typedef uint32_t mcuxClResource_HwId_t;
typedef uint32_t mcuxClResource_HwStatus_t;
typedef uint32_t mcuxClResource_Interrupt_t;

/**
 * @}
 */ /* mcuxClResource_Types */


/**********************************************
 * CONSTANTS
 **********************************************/
/**
 * @defgroup mcuxClResource_Constants mcuxClResource_Constants
 * @brief Defines all constants of @ref mcuxClResource
 * @ingroup mcuxClResource
 * @{
 */

/**
 * @defgroup MCUXCLRESOURCE_STATUS_  mcuxClResource return code definitions
 * @{
 */
#define MCUXCLRESOURCE_STATUS_OK           ((mcuxClResource_Status_t) 0x0CCC2E03u)  ///< Resource operation successful
#define MCUXCLRESOURCE_STATUS_UNAVAILABLE  ((mcuxClResource_Status_t) 0x0CCC5334u)  ///< Resource request failed
#define MCUXCLRESOURCE_STATUS_ERROR        ((mcuxClResource_Status_t) 0x0CCC5330u)  ///< Error occurred during Resource operation
#define MCUXCLRESOURCE_STATUS_FAULT_ATTACK ((mcuxClResource_Status_t) 0x0CCCF0F0u)  ///< Fault attack detected

/**@}*/

/**
 * @defgroup MCUXCLRESOURCE_HWSTATUS_ mcuxClResource status of HW resource and option to request HW resource
 * @brief Defines of hardware request options
 * @{
 */
#define MCUXCLRESOURCE_HWSTATUS_SIZE_IN_BITS        (2u)  ///< bit length of HW request option
#define MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE       ((mcuxClResource_HwStatus_t) 0x01u)  ///< option to request HW as interruptible
#define MCUXCLRESOURCE_HWSTATUS_NON_INTERRUPTABLE   ((mcuxClResource_HwStatus_t) 0x02u)  ///< option to request HW as non-interruptible


/**@}*/

/**
 * @}
 */ /* mcuxClResource_Constants */


#endif /* MCUXCLRESOURCE_TYPES_H_ */
