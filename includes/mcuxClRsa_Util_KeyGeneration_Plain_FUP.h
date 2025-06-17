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

MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_Util_KeyGeneration_Plain_BlindPQ_FUP,
    FUP_CRC_PLACEHOLDER,
    FUP_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_P_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_P,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_RAND),
    FUP_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_Q_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_Q,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_RAND)
);
MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_Util_KeyGeneration_Plain_ComputeNbAndRandSquare_FUP,
    FUP_CRC_PLACEHOLDER,
    FUP_MC2_PM(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_N_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_P_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_Q_B),
    FUP_OP1_MUL(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_RAND_SQUARE,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_RAND,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_PLAIN_RAND)
);
