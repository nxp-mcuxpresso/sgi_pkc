/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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

#include <stdint.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslAnalysis.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxCsslMemory_OK_hi16               [MCUXCSSLMEMORY_STATUS_OK                >> 16u];
volatile uint8_t mcuxCsslMemory_EQUAL_hi16            [MCUXCSSLMEMORY_STATUS_EQUAL             >> 16u];
volatile uint8_t mcuxCsslMemory_NOT_EQUAL_hi16        [MCUXCSSLMEMORY_STATUS_NOT_EQUAL         >> 16u];
volatile uint8_t mcuxCsslMemory_INVALID_PARAMETER_hi16[MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER >> 16u];
volatile uint8_t mcuxCsslMemory_FAULT_hi16            [MCUXCSSLMEMORY_STATUS_FAULT             >> 16u];

volatile uint8_t mcuxCsslMemory_OK_lo16               [MCUXCSSLMEMORY_STATUS_OK                & 0xFFFFu];
volatile uint8_t mcuxCsslMemory_EQUAL_lo16            [MCUXCSSLMEMORY_STATUS_EQUAL             & 0xFFFFu];
volatile uint8_t mcuxCsslMemory_NOT_EQUAL_lo16        [MCUXCSSLMEMORY_STATUS_NOT_EQUAL         & 0xFFFFu];
volatile uint8_t mcuxCsslMemory_INVALID_PARAMETER_lo16[MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER & 0xFFFFu];
volatile uint8_t mcuxCsslMemory_FAULT_lo16            [MCUXCSSLMEMORY_STATUS_FAULT             & 0xFFFFu];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
