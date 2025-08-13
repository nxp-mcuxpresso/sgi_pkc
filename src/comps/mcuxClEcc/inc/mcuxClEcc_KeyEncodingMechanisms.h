/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @file  mcuxClEcc_KeyEncodingMechanisms.h
 * @brief Definition of internal key types in mcuxClEcc component
 */

#ifndef MCUXCLECC_KEYENCODINGMECHANISMS_H_
#define MCUXCLECC_KEYENCODINGMECHANISMS_H_

#include <mcuxClKey_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Key encoding types are provided as external API for the user/customer, and never used internally.")

/**********************************************************/
/* WeierECC key encoding                                  */
/**********************************************************/

/**
 * @brief Key encoding descriptor for a WeierECC private key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_WeierECC_PrivateKey_Plain;
/**
 * @brief Key encoding for a WeierECC private key.
 */
#define mcuxClEcc_Encoding_WeierECC_PrivateKey_Plain &mcuxClEcc_EncodingDescriptor_WeierECC_PrivateKey_Plain

/**
 * @brief Key encoding descriptor for a WeierECC public key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_WeierECC_PublicKey_Plain;
/**
 * @brief Key encoding for a WeierECC public key.
 */
#define mcuxClEcc_Encoding_WeierECC_PublicKey_Plain &mcuxClEcc_EncodingDescriptor_WeierECC_PublicKey_Plain

/**********************************************************/
/* MontDH key encoding                                    */
/**********************************************************/

/**
 * @brief Key encoding descriptor for a MontDH private key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_MontDH_PrivateKey_Plain;
/**
 * @brief Key encoding for a MontDH private key.
 */
#define mcuxClEcc_Encoding_MontDH_PrivateKey_Plain &mcuxClEcc_EncodingDescriptor_MontDH_PrivateKey_Plain

/**
 * @brief Key encoding descriptor for a MontDH public key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_MontDH_PublicKey_Plain;
/**
 * @brief Key encoding for a MontDH public key.
 */
#define mcuxClEcc_Encoding_MontDH_PublicKey_Plain &mcuxClEcc_EncodingDescriptor_MontDH_PublicKey_Plain

/**********************************************************/
/* EdDSA key encoding                                    */
/**********************************************************/

/**
 * @brief Key encoding descriptor for a EdDSA private key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_EdDSA_PrivateKey_Plain;
/**
 * @brief Key encoding for a EdDSA private key.
 */
#define mcuxClEcc_Encoding_EdDSA_PrivateKey_Plain &mcuxClEcc_EncodingDescriptor_EdDSA_PrivateKey_Plain

/**
 * @brief Key encoding descriptor for a EdDSA public key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_EdDSA_PublicKey_Plain;
/**
 * @brief Key encoding for a EdDSA public key.
 */
#define mcuxClEcc_Encoding_EdDSA_PublicKey_Plain &mcuxClEcc_EncodingDescriptor_EdDSA_PublicKey_Plain

MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_KEYENCODINGMECHANISMS_H_ */
