/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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
 * @file  mcuxClEcc_Internal_Random_FUP.c
 * @brief mcuxClEcc: FUP program for internal random function
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_PkcWaLayout.h>
#include <internal/mcuxClEcc_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_ReduceRandomModModulus[4] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x5eu,0xe4u,0x43u,0x38u},{0x80u,0x33u,0x19u,0x19u,0x04u,0x1bu},{0x00u,0x15u,0x1bu,0x1bu,0x02u,0x1du},{0x00u,0x1au,0x1du,0x1du,0x02u,0x05u}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()


/* Preparation of random value in [1,modulus-1]              */
