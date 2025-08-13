/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
 * @file  mcuxClPkc_BasicDefs.h
 * @brief Primitive defines for PKC
 */

#ifndef MCUXCLPKC_BASICDEFS_H_
#define MCUXCLPKC_BASICDEFS_H_

#include <platform_specific_headers.h>

#include <mcuxClCore_Platform.h>
#include <mcuxClToolchain.h>

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_SfrAccess.h>

/**********************************************************/
/* Internal PKC definitions                               */
/**********************************************************/
#define MCUXCLPKC_RAM_SIZE        0x00002000u         ///< PKC workarea size = 8 KByte
#define MCUXCLPKC_RAM_OFFSET_MASK 0x00001FFFu         ///< Mask to extract PKC offset from CPU pointer
#define MCUXCLPKC_LOG2_WORDSIZE     3u                ///< log2(PKC wordsize in byte)

#define MCUXCLPKC_RAM_OFFSET_MIN    0u                ///< Minimum (included) of PKC operand offset
#define MCUXCLPKC_RAM_OFFSET_MAX    MCUXCLPKC_RAM_SIZE ///< Maximum (not included) of PKC operand offset
#define MCUXCLPKC_RAM_START_ADDRESS PKC_RAM_ADDR      ///< PKC workarea address

/** Check if an address is in the PKC RAM */
#define MCUXCLPKC_IS_PKC_RAM(address) \
  (((uint32_t)(address) >= (uint32_t)MCUXCLPKC_RAM_START_ADDRESS) && \
   ((uint32_t)(address) < (uint32_t)MCUXCLPKC_RAM_START_ADDRESS + MCUXCLPKC_RAM_SIZE))

#endif /* MCUXCLPKC_BASICDEFS_H_ */
