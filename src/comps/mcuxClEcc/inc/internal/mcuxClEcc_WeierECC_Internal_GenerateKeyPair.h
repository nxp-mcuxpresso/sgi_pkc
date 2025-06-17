/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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
 * @file  mcuxClEcc_WeierECC_Internal_GenerateKeyPair.h
 * @brief internal header for KeyGeneration over Weierstrass curve
 */


#ifndef MCUXCLECC_WEIERECC_INTERNAL_GENERATEKEYPAIR_H_
#define MCUXCLECC_WEIERECC_INTERNAL_GENERATEKEYPAIR_H_


#include <mcuxClCore_Platform.h>
#include <mcuxClKey_Types.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClSession.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Function implementing WeierECC key pair generation.
 * @api
 *
 * This function generates an ECC key pair for usage within WeierECC protocols such as ECDSA and ECDH.
 *
 * @param      pSession             Handle for the current CL session.
 * @param[in]  generation           Key generation algorithm specifier.
 * @param[out] privKey              Key handle for the generated private key.
 * @param[out] pubKey               Key handle for the generated public key.
 *
 * @attention This function uses DRBG and PRNG. Caller needs to check if DRBG and PRNG are ready.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_WeierECC_GenerateKeyPair, mcuxClKey_KeyGenFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_WeierECC_GenerateKeyPair(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Generation_t generation,
    mcuxClKey_Handle_t privKey,
    mcuxClKey_Handle_t pubKey
    );


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_WEIERECC_INTERNAL_GENERATEKEYPAIR_H_ */
