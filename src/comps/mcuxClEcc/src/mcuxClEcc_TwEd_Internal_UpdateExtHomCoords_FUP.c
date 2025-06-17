/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @file  mcuxClEcc_TwEd_Internal_UpdateExtHomCoords_FUP.c
 * @brief FUP programs used in ECC functions for Twisted Edwards curve
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_TwEd_Internal_PkcWaLayout.h>
#include <internal/mcuxClEcc_TwEd_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_TwEd_UpdateExtHomCoords[11] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x5cu,0x39u,0x86u,0x79u},{0x80u,0x00u,0x04u,0x19u,0x00u,0x1bu},{0x80u,0x2au,0x00u,0x1bu,0x00u,0x04u},{0x80u,0x00u,0x06u,0x19u,0x00u,0x1bu},{0x80u,0x2au,0x00u,0x1bu,0x00u,0x06u},{0x10u,0x00u,0xa7u,0xb6u,0xecu,0x95u},{0x80u,0x00u,0x05u,0x19u,0x00u,0x1bu},{0x80u,0x2au,0x00u,0x1bu,0x00u,0x05u},{0x10u,0x00u,0x94u,0xb4u,0x8cu,0xa7u},{0x80u,0x00u,0x07u,0x19u,0x00u,0x1bu},{0x80u,0x2au,0x00u,0x1bu,0x00u,0x07u}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()



MCUX_CSSL_ANALYSIS_START_PATTERN_URL_IN_COMMENTS()
/**
 * FUP program to update extend homogeneous coordinates of point with new random Z in [1, p-1]
 *
 * Prerequisites:
 *  - TWED_V0 contains the X-coordinate of point
 *  - TWED_V1 contains the Y-coordinate of point
 *  - TWED_V2 contains the T-coordinate of point
 *  - TWED_V3 contains the Z-coordinate of point
 *  - ECC_T0 contains random number in range [1, p-1] to update new Z = TWED_Z * ECC_T0
 *
 * Result:
 *  - Buffers TWED_V0, TWED_V1, TWED_V2, TWED_V3
 *    contain the new (X*ECC_T0:Y*ECC_T0:T*ECC_T0:Z*ECC_T0) all in range [1, p-1]
 *  - Buffers ECC_T1 corrupted
 */
MCUX_CSSL_ANALYSIS_STOP_PATTERN_URL_IN_COMMENTS()

