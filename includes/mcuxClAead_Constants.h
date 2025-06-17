/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023, 2025 NXP                                           */
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

/** @file  mcuxClAead_Constants.h
 *  @brief Constants for use with the mcuxClAead component */

#ifndef MCUXCLAEAD_CONSTANTS_H_
#define MCUXCLAEAD_CONSTANTS_H_

/**
 * @defgroup mcuxClAead_Constants mcuxClAead_Constants
 * @brief Constants of @ref mcuxClAead component
 * @ingroup mcuxClAead
 * @{
 */

#include <mcuxClConfig.h> // Exported features flags header

/* Error codes */
#define MCUXCLAEAD_STATUS_ERROR                        ((mcuxClAead_Status_t) 0x01115330u)  ///< Error occured during Aead operation
// TODO CLNS-17634: delete from Lib, no longer needed due to MCUXCLSESSION_STATUS_ERROR_MEMORY_ALLOCATION
#define MCUXCLAEAD_STATUS_ERROR_MEMORY_ALLOCATION      ((mcuxClAead_Status_t) 0x0111533Cu)  ///< Memory allocation error detected
#define MCUXCLAEAD_STATUS_FAULT_ATTACK                 ((mcuxClAead_Status_t) 0x0111F0F0u)  ///< Aead function returned fault attack
#define MCUXCLAEAD_STATUS_OK                           ((mcuxClAead_Status_t) 0x01112E03u)  ///< Aead function returned successfully
#define MCUXCLAEAD_STATUS_INVALID_PARAM                ((mcuxClAead_Status_t) 0x011153F8u)  ///< Aead function parameter invalid
#define MCUXCLAEAD_STATUS_INVALID_TAG                  ((mcuxClAead_Status_t) 0x011189F8u)  ///< Aead function tag invalid

/**@}*/

#endif /* MCUXCLAEAD_CONSTANTS_H_ */
