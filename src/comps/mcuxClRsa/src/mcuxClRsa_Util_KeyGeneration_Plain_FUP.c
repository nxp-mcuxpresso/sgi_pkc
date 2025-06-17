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

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClRsa_Util_KeyGeneration_Plain_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClRsa_Util_KeyGeneration_Plain_BlindPQ_FUP[3] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x27u,0x8bu,0x03u,0xa4u},{0xc0u,0x9du,0x00u,0x05u,0x00u,0x06u},{0xc0u,0x9du,0x01u,0x05u,0x01u,0x07u}};
const mcuxClPkc_FUPEntry_t mcuxClRsa_Util_KeyGeneration_Plain_ComputeNbAndRandSquare_FUP[3] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xb8u,0xbdu,0x93u,0xacu},{0xc0u,0x13u,0x06u,0x07u,0x06u,0x08u},{0x00u,0x00u,0x05u,0x05u,0x05u,0x09u}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()


/*
 * FUP to blind p and q
 */

/*
 * FUP to compute Nb and RandSquare
 */

