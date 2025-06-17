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
#include <internal/mcuxClRsa_ModInv_FUP.h>

MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_ModInv_ReduceBlindedData_FUP,
    FUP_CRC_PLACEHOLDER,
    FUP_MC2_MR(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_X, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD),
    FUP_MC1_MM(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_X, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_R, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD),
    FUP_MC1_MS(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD)
);
