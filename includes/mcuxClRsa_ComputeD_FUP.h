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

MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_ComputeD_Steps12_FUP,
    FUP_CRC_PLACEHOLDER,
    /* Compute p-1 */
    FUP_OP1_SUB_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PSUB1, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_P,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_CONSTANT),
    /* Compute (p-1)*b */
    FUP_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PSUB1_B, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PSUB1,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_RND),
    /* Compute q-1 */
    FUP_OP1_SUB_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_Q,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_CONSTANT),
    /* Compute (q-1)*b */
    FUP_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1_B, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_RND),
);
MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_ComputeD_Steps3_FUP,
    FUP_CRC_PLACEHOLDER,
    /* Compute phi_b = ((p-1)*b)*((q-1)*b) */
    FUP_MC2_PM(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PHI_B, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PSUB1_B, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1_B),
    /* Compute gcd_b = gcd((p-1)*b,(q-1)*b) in QSUB1_B */
    FUP_MC2_GCD(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PSUB1_B, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1_B),
    /* for both operand are congruent 2 mod 4, the result should be left shift by 1 bit */
    FUP_OP2_SHL(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1_B, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_CONSTANT)
);
