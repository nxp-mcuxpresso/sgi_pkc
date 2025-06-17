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

MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDP_FUP,
    FUP_CRC_PLACEHOLDER,
    FUP_OP1_SUB_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_T3,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_P,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_CONSTANT1),
    FUP_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_T1,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_T3,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_RAND),
    FUP_OP1_OR_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_T2,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_E,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_CONSTANT0)
);
MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDQ_FUP,
    FUP_CRC_PLACEHOLDER,
    FUP_OP1_SUB_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_T3,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_Q,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_CONSTANT1),
    FUP_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_T1,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_T3,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_RAND),
    FUP_OP1_OR_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_T2,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_E,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_CONSTANT0)
);
MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_Util_KeyGeneration_Crt_BlindPQ_FUP,
    FUP_CRC_PLACEHOLDER,
    FUP_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_P_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_P,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_RAND),
    FUP_MC2_PM_PATCH(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_Q_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_Q,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_RAND)
);
MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_Util_KeyGeneration_Crt_ComputeNbAndRandSquare_FUP,
    FUP_CRC_PLACEHOLDER,
    FUP_MC2_PM(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_N_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_P_B,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_Q_B),
    FUP_OP1_MUL(MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_RAND_SQUARE,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_RAND,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_KEYGENERATION_CRT_RAND)
);
