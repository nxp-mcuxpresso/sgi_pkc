/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * @file  mcuxClHmac_Constants.h
 * @brief Constants for the mcuxClHmac component
 */

#ifndef MCUXCLHMAC_CONSTANTS_H_
#define MCUXCLHMAC_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClHashModes_Constants.h>

/**
 * @defgroup mcuxClHmac_Constants mcuxClHmac_Constants
 * @brief Constants of @ref mcuxClHmac component
 * @ingroup mcuxClHmac
 * @{
 */

/* Output sizes */

#define MCUXCLHMAC_MAX_OUTPUT_SIZE               (MCUXCLHASH_MAX_OUTPUT_SIZE)
#define MCUXCLHMAC_MAX_OUTPUT_SIZE_IN_WORDS      (MCUXCLHMAC_MAX_OUTPUT_SIZE / sizeof(uint32_t))

/** @}*/

#endif /* MCUXCLHMAC_CONSTANTS_H_ */
