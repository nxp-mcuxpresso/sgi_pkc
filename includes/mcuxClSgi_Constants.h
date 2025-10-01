/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

/** @file  mcuxClSgi_Constants.h
 *  @brief SGI constant header.
 * This header exposes constants used by the @ref mcuxClSgi functions. */

/** @defgroup mcuxClSgi mcuxClSgi
 *  @brief Sgi component
 *
 * */

#include <mcuxClSgi_Types.h>

/**
 * @defgroup mcuxClSgi_Constants mcuxClSgi_Constants
 * @brief Defines all constants used by the @ref mcuxClSgi functions.
 * @ingroup mcuxClSgi
 * @{
 */

#ifndef MCUXCLSGI_CONSTANTS_H
#define MCUXCLSGI_CONSTANTS_H

/**********************************************
 * CONSTANTS
 **********************************************/

/**
 * @defgroup MCUXCLSGI_STATUS_ MCUXCLSGI_STATUS_
 * @brief Defines valid mcuxClSgi function return codes
 * @ingroup mcuxClSgi_Types_Macros
 * @{
 */
/* Status/error codes */
#define MCUXCLSGI_STATUS_ERROR                   ((mcuxClSgi_Status_t) 0x0FFF5330U) ///< An error occurred during an SGI operation
#define MCUXCLSGI_STATUS_UNWRAP_ERROR            ((mcuxClSgi_Status_t) 0x0FFF53B8U) ///< An error occurred during SGI key unwrap, an SGI reset or FULL_FLUSH has to be performed to clear this sticky error
#define MCUXCLSGI_STATUS_KEYSIZE_NOT_SUPPORTED   ((mcuxClSgi_Status_t) 0x0FFF5374U) ///< The given key size is not supported for the operation
#define MCUXCLSGI_STATUS_OK                      ((mcuxClSgi_Status_t) 0x0FFF2E03U) ///< The operation was successful and no SGI error occurred
#define MCUXCLSGI_STATUS_FAULT                   ((mcuxClSgi_Status_t) 0x0FFFF0F0U) ///< Fault attack detected

/**
 * @}
 */

#endif  /* MCUXCLSGI_CONSTANTS_H */

/**
 * @}
 */
