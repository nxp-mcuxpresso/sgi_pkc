/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
 * @file  mcuxClFfdh_KeyEncodingMechanisms.h
 * @brief Definition of internal key types in mcuxClFfdh component
 */

#ifndef MCUXCLFFDH_KEYENCODINGMECHANISMS_H
#define MCUXCLFFDH_KEYENCODINGMECHANISMS_H

#include <mcuxClKey_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Key encoding types are provided as external API for the user/customer, and never used internally.")

/**********************************************************/
/* FFDH key encoding                                      */
/**********************************************************/

/**
 * @brief Key encoding descriptor for a FFDH private key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClFfdh_EncodingDescriptor_PrivateKey_Plain;
/**
 * @brief Key encoding for a FFDH private key.
 */
#define mcuxClFfdh_Encoding_PrivateKey_Plain &mcuxClFfdh_EncodingDescriptor_PrivateKey_Plain

/**
 * @brief Key encoding descriptor for a FFDH public key.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClFfdh_EncodingDescriptor_PublicKey_Plain;
/**
 * @brief Key encoding for a FFDH public key.
 */
#define mcuxClFfdh_Encoding_PublicKey_Plain &mcuxClFfdh_EncodingDescriptor_PublicKey_Plain

MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLFFDH_KEYENCODINGMECHANISMS_H */
