/*--------------------------------------------------------------------------*/
/* Copyright 2022-2026 NXP                                                  */
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

/**
 * @file  mcuxClEcc_EdDSA_Internal_Hash.h
 * @brief internal header for abstracting hash calls in mcuxClEcc EdDSA
 */


#ifndef MCUXCLECC_EDDSA_INTERNAL_HASH_H_
#define MCUXCLECC_EDDSA_INTERNAL_HASH_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClHash_Types.h>
#include <mcuxClHash_Functions.h>
#include <mcuxClHash_Constants.h>

#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClHash_Internal.h>


/**
 * @brief Compute private key hash and store it in PKC workarea
 *        Function to compute private key hash and store it in PKC workarea.
 *        Since the parameter b of both Ed25519 and Ed448 is a multiple of 8,
 *        byte length of private key hash (= 2b/8) can be derived from
 *        byte length of private key (= b/8).
 *
 * @param pSession Session handle
 * @param pDomainParams EdDSA domain parameters
 * @param buffPrivKey Buffer containing private key
 * @param buffPrivKeyHash Buffer to store hash result
 * @param privKeyLen Length of private key in bytes
 *
 * @note Data Integrity: EXPUNGE: buffPrivKey + buffPrivkeyHash + privkeyLen
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_EdDSA_KeyGen_HashPrivKey)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_EdDSA_KeyGen_HashPrivKey(
    mcuxClSession_Handle_t pSession,
    const mcuxClEcc_EdDSA_DomainParams_t *pDomainParams,
    mcuxCl_InputBuffer_t buffPrivKey,
    mcuxCl_Buffer_t buffPrivKeyHash,
    uint32_t privKeyLen);


/**
 * @brief Calculate hash for EdDSA sign/verify operations
 * Function to compute input hash and store it in PKC workarea.
 * Since the parameter b of both Ed25519 and Ed448 is a multiple of 8,
 * byte length of hash (= 2b/8) can be derived from
 * byte length of encoded public key (= b/8).
 *
 * Computes hash of: prefix || signatureR || pubKey || input message
 *
 * @param pSession Session handle
 * @param pDomainParams EdDSA domain parameters
 * @param pCtx Hash context
 * @param hashAlg Hash algorithm to use
 * @param pHashPrefix Pointer to hash prefix data
 * @param hashPrefixLen Length of hash prefix
 * @param buffSignatureR Buffer containing signature R component
 * @param signatureRLen Length of signature R
 * @param pPubKey Pointer to public key
 * @param pubKeyLen Length of public key
 * @param buffIn Buffer containing input message
 * @param inSize Size of input message
 * @param buffOutput Buffer to store hash output
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_EdDSA_SignVerify_CalcHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_EdDSA_SignVerify_CalcHash(
    mcuxClSession_Handle_t pSession,
    const mcuxClEcc_EdDSA_DomainParams_t *pDomainParams,
    mcuxClHash_Context_t pCtx,
    const uint8_t *pHashPrefix,
    uint32_t hashPrefixLen,
    mcuxCl_InputBuffer_t buffSignatureR,
    uint32_t signatureRLen,
    const uint8_t *pPubKey,
    uint32_t pubKeyLen,
    mcuxCl_InputBuffer_t buffIn,
    uint32_t inSize,
    mcuxCl_Buffer_t buffOutput);

#endif /* MCUXCLECC_EDDSA_INTERNAL_HASH_H_ */
