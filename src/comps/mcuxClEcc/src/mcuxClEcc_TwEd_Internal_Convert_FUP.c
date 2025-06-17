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
 * @file  mcuxClEcc_TwEd_Internal_Convert_FUP.c
 * @brief mcuxClEcc: FUP programs for coordinate conversion on twisted Edwards curves
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_TwEd_Internal.h>
#include <internal/mcuxClEcc_TwEd_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_TwEd_ConvertAffineToExtHom[8] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xf5u,0x89u,0x83u,0x10u},{0x80u,0x00u,0x04u,0x05u,0x00u,0x19u},{0x80u,0x00u,0x19u,0x3cu,0x00u,0x06u},{0x80u,0x2au,0x00u,0x06u,0x00u,0x06u},{0x80u,0x00u,0x04u,0x3cu,0x00u,0x19u},{0x80u,0x2au,0x00u,0x19u,0x00u,0x04u},{0x80u,0x00u,0x05u,0x3cu,0x00u,0x19u},{0x80u,0x2au,0x00u,0x19u,0x00u,0x05u}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()



/* Prerequisites:
 *  - Affine coordinates x and y are stored in TWED_V0 and TWED_V1 in MR
 *  - TWED_PP_Z contains Z-coordinate to be used for conversion to extended twisted Edwards coordinates in MR in range [0,p-1]
 *
 * Result:
 *  - TWED_V0, TWED_V1, TWED_V2 contain the extended twisted Edwards coordinates X = x*Z, Y = y*Z, T = x*y*Z in MR */
