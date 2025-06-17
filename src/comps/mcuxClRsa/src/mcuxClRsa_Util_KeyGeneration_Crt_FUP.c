/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023-2024 NXP                                            */
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
#include <internal/mcuxClRsa_Util_KeyGeneration_Crt_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClRsa_Util_KeyGeneration_Crt_BlindPQ_FUP[3] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xc5u,0x58u,0x1cu,0x63u},{0xc0u,0x9du,0x01u,0x0au,0x01u,0x0bu},{0xc0u,0x9du,0x02u,0x0au,0x02u,0x0cu}};
const mcuxClPkc_FUPEntry_t mcuxClRsa_Util_KeyGeneration_Crt_ComputeNbAndRandSquare_FUP[3] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x78u,0x60u,0x80u,0xa5u},{0xc0u,0x13u,0x0bu,0x0cu,0x0bu,0x0du},{0x00u,0x00u,0x0au,0x0au,0x0au,0x0eu}};
const mcuxClPkc_FUPEntry_t mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDP_FUP[4] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x61u,0xbdu,0xacu,0x80u},{0x00u,0x1bu,0x01u,0x01u,0x10u,0x08u},{0xc0u,0x9du,0x08u,0x0au,0x08u,0x06u},{0x00u,0x1eu,0x00u,0x00u,0x0fu,0x07u}};
const mcuxClPkc_FUPEntry_t mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDQ_FUP[4] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x61u,0xbdu,0xafu,0x83u},{0x00u,0x1bu,0x02u,0x02u,0x10u,0x08u},{0xc0u,0x9du,0x08u,0x0au,0x08u,0x06u},{0x00u,0x1eu,0x00u,0x00u,0x0fu,0x07u}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()


/*
 * FUP to compute (p-1)*b and copy E
 */

/*
 * FUP to compute (q-1)*b and copy E
 */

/*
 * FUP to blind p and q
 */

/*
 * FUP to compute Nb and RandSquare
 */

