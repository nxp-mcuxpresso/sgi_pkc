/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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
 * @file  mcuxClEcc_SignatureMechanisms.c
 * @brief mcuxClEcc: implementation of ECC related signature mode descriptors
 */

#include <mcuxClSignature.h>
#include <internal/mcuxClSignature_Internal.h>
#include <mcuxClMac.h>

#include <mcuxClEcc.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClEcc_EdDSA_Internal.h>

#include <internal/mcuxClEcc_ECDSA_Internal.h>


const mcuxClSignature_ModeDescriptor_t mcuxClSignature_ModeDescriptor_ECDSA =
{
  .pSignFct = mcuxClEcc_ECDSA_GenerateSignature,
  .protection_token_sign = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ECDSA_GenerateSignature),
  .pVerifyFct = mcuxClEcc_ECDSA_VerifySignature,
  .protection_token_verify = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ECDSA_VerifySignature),
  .pProtocolDescriptor = (const void *) &mcuxClEcc_ECDSA_ProtocolDescriptor
};


/* Signature mode structure for Ed25519 */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClSignature_ModeDescriptor_t mcuxClSignature_ModeDescriptor_Ed25519 =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  .pSignFct = mcuxClEcc_EdDSA_GenerateSignature,
  .protection_token_sign = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateSignature),
  .pVerifyFct = mcuxClEcc_EdDSA_VerifySignature,
  .protection_token_verify = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_VerifySignature),
  .pProtocolDescriptor = (const void *) &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor
};

