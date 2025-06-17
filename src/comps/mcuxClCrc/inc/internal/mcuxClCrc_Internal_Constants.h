/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2025 NXP                                                 */
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
 * @file  mcuxClCrc_Internal_Constants.h
 * @brief Internal constants of the mcuxClCrc component
 */

#ifndef MCUXCLCRC_INTERNAL_CONSTANTS_H_
#define MCUXCLCRC_INTERNAL_CONSTANTS_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClCrc_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClCrc_Internal_Constants mcuxClCrc_Internal_Constants
 * @brief Internal constants of the @ref mcuxClCrc component
 * @ingroup mcuxClCrc
 * @{
 */

/**
 * @defgroup mcuxClCrc_Internal_Constants_Defines mcuxClCrc_Internal_Constants_Defines
 * @brief Defines the CRC constants of component @ref mcuxClCrc
 * @ingroup mcuxClCrc_Internal_Constants
 * @{
 */


#define MCUXCLCRC_DEFAULT_SEED_16 (0xFFFFu)       ///< The initial seed of the default 16-bit CRC algorithm
#define MCUXCLCRC_DEFAULT_SEED_32 (0xFFFFFFFFu)   ///< The initial seed of the default 32-bit CRC algorithm

#define MCUXCLCRC_DEFAULT_POLY_16 (0x00001021u)   ///< The polynomial of the default 16-bit CRC algorithm
#define MCUXCLCRC_DEFAULT_POLY_32 (0x04C11DB7u)   ///< The polynomial of the default 32-bit CRC algorithm

#define MCUXCLCRC_DEFAULT_CRC_OUT_MASK_16 ((uint16_t)0xFFFFu)       ///< The output mask of the default 16-bit CRC algorithm
#define MCUXCLCRC_DEFAULT_CRC_OUT_MASK_32 ((uint32_t)0xFFFFFFFFu)   ///< The output mask of the default 32-bit CRC algorithm

#define MCUXCLCRC_STATUS_FAULT_ATTACK      ((mcuxClCrc_Status_t) 0x0234F0F0u)   ///< Crc function detected a fault attack

/**
 * @}
 */ /* mcuxClCrc_Internal_Constants_Defines */

/**
 * @}
 */ /* mcuxClCrc_Internal_Constants */
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLCRC_INTERNAL_CONSTANTS_H_ */
