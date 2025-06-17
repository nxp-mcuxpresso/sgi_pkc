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

/** @file  mcuxClCipher_Constants.h
 *  @brief Constants for use with the mcuxClCipher component
 */

#ifndef MCUXCLCIPHER_CONSTANTS_H_
#define MCUXCLCIPHER_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header

/**
 * @defgroup mcuxClCipher_Constants mcuxClCipher_Constants
 * @brief Constants of @ref mcuxClCipher component
 * @ingroup mcuxClCipher
 * @{
 */

/* Status codes */
#define MCUXCLCIPHER_STATUS_ERROR                        ((mcuxClCipher_Status_t) 0x02225330u) ///< Functional error detected in cipher operation
#define MCUXCLCIPHER_STATUS_FAILURE                      ((mcuxClCipher_Status_t) 0x02225334u) ///< Functional failure detected
#define MCUXCLCIPHER_STATUS_INVALID_INPUT                ((mcuxClCipher_Status_t) 0x022253F8u) ///< Invalid input provided
// TODO CLNS-17634: delete from Lib, no longer needed due to MCUXCLSESSION_STATUS_ERROR_MEMORY_ALLOCATION
#define MCUXCLCIPHER_STATUS_ERROR_MEMORY_ALLOCATION      ((mcuxClCipher_Status_t) 0x0222533Cu) ///< Memory allocation error detected
#define MCUXCLCIPHER_STATUS_FAULT_ATTACK                 ((mcuxClCipher_Status_t) 0x0222F0F0u) ///< Fault attack detected
#define MCUXCLCIPHER_STATUS_OK                           ((mcuxClCipher_Status_t) 0x02222E03u) ///< Blocking operation finished successfully
#define MCUXCLCIPHER_STATUS_JOB_STARTED                  ((mcuxClCipher_Status_t) 0x02222E47u) ///< Non-blocking operation started successfully
#define MCUXCLCIPHER_STATUS_JOB_COMPLETED                ((mcuxClCipher_Status_t) 0x02222E8Bu) ///< Non-blocking operation finished successfully

/** @}*/
#endif /* MCUXCLCIPHER_CONSTANTS_H_ */
