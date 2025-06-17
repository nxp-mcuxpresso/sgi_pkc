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
#include <internal/mcuxClRsa_ComputeD_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClRsa_ComputeD_Steps12_FUP[5] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x61u,0x83u,0xbeu,0x3fu},{0x00u,0x1bu,0x00u,0x00u,0x0du,0x07u},{0xc0u,0x9du,0x07u,0x06u,0x07u,0x09u},{0x00u,0x1bu,0x01u,0x01u,0x0du,0x08u},{0xc0u,0x9du,0x08u,0x06u,0x08u,0x0au}};
const mcuxClPkc_FUPEntry_t mcuxClRsa_ComputeD_Steps3_FUP[4] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xbeu,0x07u,0x70u,0x06u},{0xc0u,0x13u,0x09u,0x0au,0x09u,0x05u},{0xc0u,0xa7u,0x09u,0x09u,0x0au,0x0au},{0x40u,0x14u,0x0au,0x0au,0x0du,0x0au}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()


/*
 * call the FUP code to do the below steps
 * 1. Compute (p-1)*b
 * 2. Compute (q-1)*b
 * 3. Compute lcm((p-1)*b,(q-1)*b) = (((p-1)*b)*((q-1)*b)) / gcd((p-1)*b,(q-1)*b)
 * 3.1 Compute phi_b = ((p-1)*b)*((q-1)*b)
 * 3.2 Compute gcd_b = gcd((p-1)*b,(q-1)*b)
 */



