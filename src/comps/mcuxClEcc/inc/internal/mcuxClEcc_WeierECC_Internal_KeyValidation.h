/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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
 * @file  mcuxClEcc_WeierECC_Internal_KeyValidation.h
 * @brief internal header for Key Validation over Weierstrass curve
 */


#ifndef MCUXCLECC_WEIERECC_INTERNAL_KEYVALIDATION_H_
#define MCUXCLECC_WEIERECC_INTERNAL_KEYVALIDATION_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClBuffer.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>

/**
 * @brief ECC public key validation function
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_WeierECC_PublicKeyValidation, mcuxClKey_ValidationFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClEcc_WeierECC_PublicKeyValidation(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key);

/**
 * @brief ECC private key validation function
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_WeierECC_PrivateKeyValidation, mcuxClKey_ValidationFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClEcc_WeierECC_PrivateKeyValidation(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key);

#endif /* MCUXCLECC_WEIERECC_INTERNAL_KEYVALIDATION_H_ */
