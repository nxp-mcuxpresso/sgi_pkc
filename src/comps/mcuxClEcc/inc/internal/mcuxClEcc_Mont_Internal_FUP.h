/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023-2024, 2026 NXP                                      */
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
 * @file  mcuxClEcc_Mont_Internal_FUP.h
 * @brief defines FUP programs byte arrays
 */


#ifndef MCUXCLECC_MONT_INTERNAL_FUP_H_
#define MCUXCLECC_MONT_INTERNAL_FUP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClPkc_FupMacros.h>


/**********************************************************/
/* FUPs for Montgomery DH functionalities                 */
/**********************************************************/

MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_LINKAGE_FUP()
/**
 * FUP program declaration mcuxClEcc_FUP_MontDhDecodeScalar
 */
#define mcuxClEcc_FUP_MontDhDecodeScalar_LEN  10u
MCUXCLPKC_FUP_EXT_ROM_DECLARE(mcuxClEcc_FUP_MontDhDecodeScalar);

/**
 * FUP program declaration mcuxClEcc_FUP_MontDhX_CalcAffineX
 */
#define mcuxClEcc_FUP_MontDhX_CalcAffineX_LEN  8u
MCUXCLPKC_FUP_EXT_ROM_DECLARE(mcuxClEcc_FUP_MontDhX_CalcAffineX);

/**
 * FUP program declaration mcuxClEcc_FUP_MontDhX_DecodeAndRandomizeX
 */
#define mcuxClEcc_FUP_MontDhX_DecodeAndRandomizeX_LEN  6u
MCUXCLPKC_FUP_EXT_ROM_DECLARE(mcuxClEcc_FUP_MontDhX_DecodeAndRandomizeX);


/**********************************************************/
/* FUPs for SecureScalarMult operation                    */
/**********************************************************/
/**
 * FUP program declaration mcuxClEcc_FUP_Mont_SecureScalarMult_UpdateAccCoords
 */
#define mcuxClEcc_FUP_Mont_SecureScalarMult_UpdateAccCoords_LEN  9u

MCUXCLPKC_FUP_EXT_ROM_DECLARE(mcuxClEcc_FUP_Mont_SecureScalarMult_UpdateAccCoords);

/**
 * FUP program declaration mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep
 */
#define mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep_Affine_LEN  19u
#define mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep_Projective_LEN  22u

MCUXCLPKC_FUP_EXT_ROM_DECLARE(mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep);

MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_LINKAGE_FUP()

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_MONT_INTERNAL_FUP_H_ */
