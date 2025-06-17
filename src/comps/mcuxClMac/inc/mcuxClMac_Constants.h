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

/**
 * @file  mcuxClMac_Constants.h
 * @brief Constants and status codes for the mcuxClMac component
 */

#ifndef MCUXCLMAC_CONSTANTS_H_
#define MCUXCLMAC_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header

/**
 * @defgroup mcuxClMac_Constants mcuxClMac_Constants
 * @brief Constants of @ref mcuxClMac component
 * @ingroup mcuxClMac
 * @{
 */

/* Status codes */
#define MCUXCLMAC_STATUS_ERROR                     ((mcuxClMac_Status_t) 0x08885330u) ///< Functional error detected in MAC operation
#define MCUXCLMAC_STATUS_FAILURE                   ((mcuxClMac_Status_t) 0x08885334u) ///< Functional failure detected
#define MCUXCLMAC_STATUS_INVALID_PARAM             ((mcuxClMac_Status_t) 0x088853F8u) ///< Invalid input provided
#define MCUXCLMAC_STATUS_FAULT_ATTACK              ((mcuxClMac_Status_t) 0x0888F0F0u) ///< Fault attack detected
#define MCUXCLMAC_STATUS_OK                        ((mcuxClMac_Status_t) 0x08882E03u) ///< Blocking operation finished successfully
#define MCUXCLMAC_STATUS_COMPARE_NOK               ((mcuxClMac_Status_t) 0x088889FCu) ///< Blocking operation finished, invalid tag detected
// TODO CLNS-17634: delete from Lib, no longer needed due to MCUXCLSESSION_STATUS_ERROR_MEMORY_ALLOCATION
#define MCUXCLMAC_STATUS_ERROR_MEMORY_ALLOCATION   ((mcuxClMac_Status_t) 0x0888533Cu) ///< Memory allocation error detected
#define MCUXCLMAC_STATUS_JOB_STARTED               ((mcuxClMac_Status_t) 0x08882E47u) ///< Non-blocking operation started successfully
#define MCUXCLMAC_STATUS_JOB_COMPLETED             ((mcuxClMac_Status_t) 0x08882EFCu) ///< Non-blocking operation finished successfully
#define MCUXCLMAC_STATUS_JOB_COMPLETED_COMPARE_NOK ((mcuxClMac_Status_t) 0x08888903u) ///< Non-blocking operation finished, invalid tag detected

/** @}*/

#endif /* MCUXCLMAC_CONSTANTS_H_ */
