/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @file  mcuxClEcc_Internal_PointComparison_FUP.c
 * @brief FUP programs for EdDSA Signature Verification
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_PointComparisonHom[10] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xf6u,0x26u,0x36u,0x35u},{0x80u,0x00u,0x04u,0x22u,0x00u,0x18u},{0x80u,0x00u,0x05u,0x22u,0x00u,0x07u},{0x80u,0x00u,0x20u,0x06u,0x00u,0x1au},{0x80u,0x00u,0x21u,0x06u,0x00u,0x08u},{0x80u,0x2au,0x10u,0x18u,0x1au,0x1cu},{0x80u,0x2au,0x10u,0x07u,0x08u,0x1du},{0x80u,0x00u,0x1cu,0x1du,0x00u,0x1eu},{0x80u,0x33u,0x1eu,0x1eu,0x00u,0x1du},{0x80u,0x2au,0x00u,0x1du,0x00u,0x1du}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()


/**
 * FUP program to check if two projective points P1 and P2 are equal
 *
 * Prerequisites:
 *  - ECC_V0 contains the X-coordinate of point P1
 *  - ECC_V1 contains the Y-coordinate of point P1
 *  - ECC_V2 contains the Z-coordinate of point P1
 *  - ECC_COORD00 contains the X-coordinate of point P2
 *  - ECC_COORD01 contains the Y-coordinate of point P2
 *  - ECC_COORD02 contains the Z-coordinate of point P2
 *
 * Result:
 *  - The zero flag is set if and only if the two points are equal
 *  - The concatenations of the coordinates are stored in ECC_S0 and ECC_S1.
 *    i.e., X'||Y' is stored in ECC_S0, X||Y is stored in ECC_S1
 */
