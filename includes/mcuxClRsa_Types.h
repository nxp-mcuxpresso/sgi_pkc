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

/**
 * @file  mcuxClRsa_Types.h
 * @brief Type definitions for the mcuxClRsa component
 */

#ifndef MCUXCLRSA_TYPES_H_
#define MCUXCLRSA_TYPES_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

/***********************************************************
 *  MACROS
 **********************************************************/

/**
 * @defgroup mcuxClRsa_Macros mcuxClRsa_Macros
 * @brief Defines all macros of @ref mcuxClRsa
 * @ingroup mcuxClRsa
 * @{
 */

/***********************************************************
 *  MACROS RELATED TO FUNCTION STATUS
 **********************************************************/

/**
 * @defgroup MCUXCLRSA_STATUS_ MCUXCLRSA_STATUS_
 * @brief Return code definitions
 * @ingroup mcuxClRsa_Macros
 * @{
 */
#define MCUXCLRSA_STATUS_SIGN_OK                            ((mcuxClRsa_Status_t) 0x0FF62E07u )  ///< RSA sign operation successful
#define MCUXCLRSA_STATUS_VERIFY_OK                          ((mcuxClRsa_Status_t) 0x0FF62E03u )  ///< RSA verify operation successful
#define MCUXCLRSA_STATUS_OK                                 ((mcuxClRsa_Status_t) 0x0FF62E17u )  ///< RSA operation was successful
#define MCUXCLRSA_STATUS_ERROR                              ((mcuxClRsa_Status_t) 0x0FF65330u )  ///< Error occurred during RSA operation
#define MCUXCLRSA_STATUS_INVALID_INPUT                      ((mcuxClRsa_Status_t) 0x0FF653F8u )  ///< Input data cannot be processed
#define MCUXCLRSA_STATUS_VERIFY_FAILED                      ((mcuxClRsa_Status_t) 0x0FF68930u )  ///< Signature verification failed
#define MCUXCLRSA_STATUS_FAULT_ATTACK                       ((mcuxClRsa_Status_t) 0x0FF6F0F0u )  ///< Fault attack detected
#define MCUXCLRSA_STATUS_KEYGENERATION_OK                   ((mcuxClRsa_Status_t) 0x0FF62E0Fu )  ///< RSA key generation operation executed successfully

/** @} */


/***********************************************************
 *  MACROS RELATED TO PUBLIC FUNCTIONS' OPTIONS
 **********************************************************/
/**
 * @defgroup MCUXCLRSA_OPTION_ MCUXCLRSA_OPTION_
 * @brief Function options definitions
 * @ingroup mcuxClRsa_Macros
 * @{
 */
/**
 * @}
 * @}
 */

/**********************************************
 * TYPEDEFS
 **********************************************/
 /**
 * @defgroup mcuxClRsa_Types mcuxClRsa_Types
 * @brief Defines all types of the @ref mcuxClRsa component
 * @ingroup mcuxClRsa
 * @{
 */

/***********************************************************
 *  TYPES RELATED TO FUNCTION STATUS
 **********************************************************/

/**
 * @brief Type for RSA status codes
 */
typedef uint32_t mcuxClRsa_Status_t;

/***********************************************************
 *  TYPES RELATED TO RSA KEY
 **********************************************************/
/**
 * @brief Structure type for Rsa key entries, specifying key entry length and data.
 */
/* Struct is packed to prevent compiler optimizations (e.g., LDR.D) on unaligned data. */
typedef struct
{
  uint8_t* pKeyEntryData;    ///< Pointer to buffer containing the key entry data in big-endian byte order
  uint32_t keyEntryLength;   ///< Byte-length of the buffer pointed to by pKeyEntryData
} __attribute__ ((packed)) mcuxClRsa_KeyEntry_t;

/**
 * @}
 */


#endif /* MCUXCLRSA_TYPES_H_ */

