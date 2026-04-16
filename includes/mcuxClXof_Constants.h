/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

/** @file  mcuxClXof_Constants.h
 *  @brief Constants for use with the mcuxClXof component */

#ifndef MCUXCLXOF_CONSTANTS_H_
#define MCUXCLXOF_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header

/**
 * @defgroup mcuxClXof_Constants mcuxClXof_Constants
 * @brief Constants of @ref mcuxClXof component
 * @ingroup mcuxClXof
 * @{
 */

#define MCUXCLXOF_STATUS_OK                                  ((mcuxClXof_Status_t) 0x06762E03u)           ///< Xof operation successful
#define MCUXCLXOF_STATUS_FAILURE                             ((mcuxClXof_Status_t) 0x06765330u)           ///< Xof operation failed
#define MCUXCLXOF_STATUS_FAULT_ATTACK                        ((mcuxClXof_Status_t) 0x0676F0F0u)           ///< Fault attack (unexpected behavior) detected

/**@}*/

#endif /* MCUXCLXOF_CONSTANTS_H_ */
