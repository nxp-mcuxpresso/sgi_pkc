/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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
 * @file  mcuxClEcc_WeierECC_Internal_DecodePoint_FUP.c
 * @brief mcuxClEcc: FUP programs used in ECC functions for NIST curves
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Weier_Internal_PkcWaLayout.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_DecodePoint_SEC_CalcAlpha[7] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xc4u,0xc9u,0x8eu,0x11u},{0x80u,0x00u,0x13u,0x16u,0x00u,0x1bu},{0x80u,0x00u,0x20u,0x16u,0x00u,0x18u},{0x80u,0x00u,0x18u,0x18u,0x00u,0x19u},{0x80u,0x21u,0x10u,0x19u,0x12u,0x19u},{0x80u,0x00u,0x18u,0x19u,0x00u,0x1au},{0x80u,0x21u,0x10u,0x1au,0x1bu,0x1au}};
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_DecodePoint_SEC_VerifyBeta[7] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xacu,0x00u,0x33u,0x98u},{0x80u,0x33u,0x1cu,0x1cu,0x00u,0x1bu},{0x80u,0x2au,0x00u,0x1bu,0x00u,0x21u},{0x80u,0x00u,0x1cu,0x1cu,0x00u,0x1bu},{0x80u,0x2au,0x10u,0x1bu,0x1au,0x1bu},{0x80u,0x33u,0x1bu,0x1bu,0x00u,0x19u},{0x80u,0x2au,0x00u,0x19u,0x00u,0x19u}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()


/* FUP program: Calculate alpha for point decoding.                     */
/*  Calculate alpha = x^3 + ax + b  in MR, will be stored in ECC_S1.    */
/*  Input: x in WEIER_XA, constant 2 in WEIER_VX0.                      */

/* FUP program: Prepare to verify the correctness of beta, i.e. verify beta^2 == alpha.  */
/*  Calculate beta in NR mod p, will be stored in WEIER_YA.                              */
/*  Calculate beta^2-alpha                                                               */
/*  Input: beta in MR in ECC_S2, alpha in MR in ECC_S1.                                  */
