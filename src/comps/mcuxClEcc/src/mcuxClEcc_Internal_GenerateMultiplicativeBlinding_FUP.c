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
 * @file  mcuxClEcc_FUP_GenerateMultiplicativeBlinding_FUP.c
 * @brief mcuxClEcc: FUP program for internal GenerateMultiplicativeBlinding function
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Internal_PkcWaLayout.h>
#include <internal/mcuxClEcc_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_GenerateMultiplicativeBlinding[7] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x67u,0x1cu,0xa8u,0x8du},{0x00u,0x1eu,0x1fu,0x1fu,0x03u,0x04u},{0xc0u,0x00u,0x1au,0x19u,0x01u,0x1fu},{0x80u,0x00u,0x1fu,0x17u,0x01u,0x1bu},{0x80u,0x33u,0x1bu,0x1bu,0x01u,0x19u},{0x80u,0x2au,0x01u,0x19u,0x01u,0x19u},{0x80u,0x2au,0x01u,0x19u,0x04u,0x1au}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()



/**
 * Prerequisites:
 * T3 = phi^-1 * rnd (opLen)
 * T0 = phi^(-1)*2^(8*(scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE) (operandSize)
 * S1 = s + rnd (scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE bytes)
 * ps1Len = (operandSize, operandSize).
 * ps2Len = (scalarPkcAlignedSize + MCUXCLPKC_WORDSIZE, operandSize).
 *
 * Results:
 * the blinded scalar sigma is contained in buffer ECC_S1 (operandSize).
 */
