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

/**
 * @file  mcuxClEcc_Weier_Internal_DiscriminantCalculate_FUP.c
 * @brief FUP program for Weierstrass curve singularity calculation
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Weier_Internal_PkcWaLayout.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_Weier_DiscriminantCalculate[13] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x09u,0x6fu,0xbcu,0x99u},{0x80u,0x21u,0x10u,0x12u,0x12u,0x1bu},{0x80u,0x00u,0x1bu,0x1bu,0x00u,0x1du},{0x80u,0x00u,0x1du,0x12u,0x00u,0x1bu},{0x80u,0x00u,0x13u,0x16u,0x00u,0x1du},{0x80u,0x21u,0x10u,0x1du,0x1du,0x1eu},{0x80u,0x21u,0x10u,0x1eu,0x1du,0x1eu},{0x80u,0x00u,0x1eu,0x1eu,0x00u,0x1cu},{0x80u,0x21u,0x10u,0x1cu,0x1cu,0x1eu},{0x80u,0x21u,0x10u,0x1eu,0x1cu,0x1eu},{0x80u,0x21u,0x10u,0x1eu,0x1bu,0x1bu},{0x80u,0x33u,0x1bu,0x1bu,0x00u,0x1eu},{0x80u,0x2au,0x00u,0x1eu,0x00u,0x1bu}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()



/* FUP program: Calculate 4*a^3 + 27*b^2 mod p  */
