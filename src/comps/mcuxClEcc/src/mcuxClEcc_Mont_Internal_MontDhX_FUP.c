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

/**
 * @file  mcuxClEcc_Mont_Internal_MontDhX_FUP.c
 * @brief FUP programs for MontDhX functions
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Mont_Internal_PkcWaLayout.h>
#include <internal/mcuxClEcc_Mont_Internal_FUP.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_FUP_PROGRAM()
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_MontDhDecodeScalar[10] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xe6u,0x5cu,0xa9u,0x88u},{0x00u,0x0fu,0x1eu,0x1eu,0x1du,0x1cu},{0x00u,0x15u,0x1cu,0x1cu,0x04u,0x1fu},{0x00u,0x14u,0x1fu,0x1fu,0x05u,0x1cu},{0x00u,0x1au,0x1cu,0x1cu,0x02u,0x1cu},{0x00u,0x17u,0x1cu,0x1cu,0x05u,0x1fu},{0x00u,0x15u,0x1du,0x1du,0x04u,0x19u},{0x00u,0x14u,0x19u,0x19u,0x05u,0x1du},{0x00u,0x17u,0x1du,0x1du,0x05u,0x19u},{0x00u,0x0fu,0x1fu,0x1fu,0x19u,0x1cu}};
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_MontDhX_CalcAffineX[8] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x0eu,0x6bu,0xc1u,0x21u},{0x80u,0x00u,0x1bu,0x16u,0x00u,0x19u},{0x80u,0x33u,0x19u,0x19u,0x00u,0x1bu},{0x80u,0x00u,0x1bu,0x1du,0x00u,0x19u},{0x80u,0x21u,0x10u,0x24u,0x1du,0x24u},{0x80u,0x00u,0x24u,0x1bu,0x00u,0x1du},{0x80u,0x2au,0x00u,0x1du,0x00u,0x1bu},{0x80u,0x2au,0x00u,0x1bu,0x19u,0x24u}};
const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_MontDhX_DecodeAndRandomizeX[6] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xa7u,0x7fu,0x78u,0xc1u},{0x00u,0x14u,0x19u,0x19u,0x04u,0x1bu},{0x00u,0x15u,0x1bu,0x1bu,0x04u,0x19u},{0x80u,0x00u,0x19u,0x16u,0x00u,0x1bu},{0x80u,0x00u,0x1bu,0x25u,0x00u,0x24u},{0x80u,0x2au,0x00u,0x24u,0x00u,0x24u}};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_FUP_PROGRAM()



/* The algorithm implemented by this FUP program to decode an encoded Curve25519 or Curve448 private key
 * only works if:
 *    c < 8*pkcWordSize
 *    0 < 8*operandSize - t + c < 8*pkcWordSize-1
 *  For the use cases Curve25519 and Curve448 these conditions are met.
 *
 * Prerequisites:
 * - Buffer ECC_S3 contain the scalar to decode
 * - Buffer ECC_T2 contain the mask to protect scalar
 * Result:
 * - The cofactorless decoded scalar k'=k/h is stored in buffer ECC_S2
 * - The Buffers ECC_T0, ECC_T2, ECC_T3 corrupted
 */



/* The FUP program decodes an x-coordinate of Curve25519 or Curve448 and converts it to a randomized projective coordinate X with a random Z-coordinate
 * Prerequisites:
 * - Buffer ECC_T0 contains the x in NR
 * - Buffer MONT_Z0 contains a random Z
 * - Buffer MONT_V0 contains the number leadingZerosP of leading zeros of p in the highest PKC word 
 * Result:
 * - Buffer MONT_X0 contains X coordinate in MR
 * - Buffer MONT_Z0 contains Z coordinate in range [1, (p+1)/2] in MR
 * Note: For Curve25519 and Curve448, we have leadingZerosP < PKC word bit length, so using those values as shift amounts doesn't cause any issues.
 */
