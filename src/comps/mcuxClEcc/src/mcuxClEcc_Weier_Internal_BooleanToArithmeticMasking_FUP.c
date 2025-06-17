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
 * @file  mcuxClEcc_Weier_BooleanToArithmeticMasking_FUP.c
 * @brief FUP program for converting boolean masking to arithmetic masking
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Weier_Internal_PkcWaLayout.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_Weier_BooleanToArithmeticMasking[8] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x2cu,0x70u,0xbeu,0x2eu},{0x40u,0x0fu,0x1cu,0x1cu,0x1au,0x18u},{0x40u,0x0bu,0x18u,0x18u,0x1au,0x18u},{0x40u,0x0fu,0x18u,0x18u,0x1cu,0x18u},{0x40u,0x0fu,0x1au,0x1au,0x1eu,0x1au},{0x40u,0x0fu,0x1cu,0x1cu,0x1au,0x1cu},{0x40u,0x0bu,0x1cu,0x1cu,0x1au,0x1cu},{0x40u,0x0fu,0x1cu,0x1cu,0x18u,0x1cu}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()



/**
 * Prerequisites: 
 * S0 - Buffer for temporary value
 * S1 - Temporary mask t
 * S2 - Masked value v
 * S3 - Mask r
 *
 * Masked value will be updated with new value
 *
 * Function psi(x, r) = x ^ r - r, and is affine over F2, see paper for details.
 *
 * The correctness of the algorithm is shown in the following paper:
 * https:(doulbe slashes)doi.org/10.1007/978-3-662-48116-5_7
 */

