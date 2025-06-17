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

/**
 *
 * @file:   size.c
 * @brief:  This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClSession_Types.h>
#include <internal/mcuxClSession_Internal_EntryExit_EarlyExit_Types.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()


volatile uint8_t mcuxClSession_Descriptor_SIZE [sizeof(mcuxClSession_Descriptor_t)];

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
volatile uint8_t mcuxClSession_Status_API_Entered_hi16           [MCUXCLSESSION_STATUS_API_ENTERED            >> 16u];
volatile uint8_t mcuxClSession_Status_API_Entered_lo16           [MCUXCLSESSION_STATUS_API_ENTERED            & 0xFFFFu];
volatile uint8_t mcuxClSession_Status_EXIT_FA_hi16               [MCUXCLSESSION_STATUS_EXIT_FA                >> 16u];
volatile uint8_t mcuxClSession_Status_EXIT_FA_lo16               [MCUXCLSESSION_STATUS_EXIT_FA                & 0xFFFFu];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

volatile uint8_t mcuxClSession_wordlen                            [sizeof(void*)];
volatile uint8_t mcuxClSession_apiCallOffset                      [offsetof(struct mcuxClSession_Descriptor, apiCall) + 1u];   /* Added +1 to avoid [0] */
volatile uint8_t mcuxClSession_apiCallFaultStatusOffset           [offsetof(struct mcuxClSession_apiCall, faultStatus) + 1u];  /* Added +1 to avoid [0] */
volatile uint8_t mcuxClSession_apiCallDiBackupOffset              [offsetof(struct mcuxClSession_apiCall, diBackup) + 1u];     /* Added +1 to avoid [0] */
volatile uint8_t mcuxClSession_apiCallPreviousOffset              [offsetof(struct mcuxClSession_apiCall, previous) + 1u];     /* Added +1 to avoid [0] */
volatile uint8_t mcuxClSession_apiCallCpuRegisterBackupOffset     [offsetof(struct mcuxClSession_apiCall, cpuRegisterBackup) + 1u];    /* Added +1 to avoid [0] */

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
