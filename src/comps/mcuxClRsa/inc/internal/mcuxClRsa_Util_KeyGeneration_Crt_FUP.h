/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023-2024, 2026 NXP                                      */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/** @file  mcuxClRsa_Util_KeyGeneration_Crt_FUP.h
*  @brief defines FUP programs byte arrays for mcuxClRsa_Util_KeyGeneration_Crt
*/
#ifndef MCUXCLRSA_UTIL_KEYGENERATION_CRT_FUP_H_
#define MCUXCLRSA_UTIL_KEYGENERATION_CRT_FUP_H_
#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>

#define mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDP_FUP_LEN  4U
#define mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDQ_FUP_LEN  4U
#define mcuxClRsa_Util_KeyGeneration_Crt_BlindPQ_FUP_LEN  3U
#define mcuxClRsa_Util_KeyGeneration_Crt_ComputeNbAndRandSquare_FUP_LEN  3U

MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_LINKAGE_FUP()
MCUXCLPKC_FUP_EXT_ROM_DECLARE(
  mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDP_FUP,
  mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDP_FUP_LEN
);

MCUXCLPKC_FUP_EXT_ROM_DECLARE(
  mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDQ_FUP,
  mcuxClRsa_Util_KeyGeneration_Crt_ParamsForDQ_FUP_LEN
);

MCUXCLPKC_FUP_EXT_ROM_DECLARE(
  mcuxClRsa_Util_KeyGeneration_Crt_BlindPQ_FUP,
  mcuxClRsa_Util_KeyGeneration_Crt_BlindPQ_FUP_LEN
);

MCUXCLPKC_FUP_EXT_ROM_DECLARE(
  mcuxClRsa_Util_KeyGeneration_Crt_ComputeNbAndRandSquare_FUP,
  mcuxClRsa_Util_KeyGeneration_Crt_ComputeNbAndRandSquare_FUP_LEN
);

MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_LINKAGE_FUP()

#endif /* MCUXCLRSA_UTIL_KEYGENERATION_CRT_FUP_H_ */
