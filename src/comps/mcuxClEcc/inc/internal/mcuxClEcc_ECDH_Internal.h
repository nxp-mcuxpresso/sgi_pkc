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
 * @file  mcuxClEcc_ECDH_Internal.h
 * @brief internal header for ECDH
 */


#ifndef MCUXCLECC_ECDH_INTERNAL_H_
#define MCUXCLECC_ECDH_INTERNAL_H_


#include <mcuxClCore_Platform.h>
#include <mcuxClKey_Types.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ECDH key agreement.
 * @api
 *
 * This function performs an ECDH key agreement to compute a shared secret between two parties.
 *
 * @param[in] pSession             pointer to #mcuxClSession_Descriptor.
 * @param[in] agreement            Key agreement algorithm specifier.
 * @param[in] key                  private key handling structure
 * @param[in] otherKey             public key handling structure
 * @param[in] additionalInputs     Key agreement additional input pointers (unused parameter)
 * @param[in] numberOfInputs       number of additional inputs (unused parameter)
 * @param[out] pOut                buffer for shared secret
 * @param[out] pOutLength          shared secret length
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_ECDH_KeyAgreement, mcuxClKey_AgreementFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_ECDH_KeyAgreement(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Agreement_t agreement,
    mcuxClKey_Handle_t key,
    mcuxClKey_Handle_t otherKey,
    mcuxClKey_Agreement_AdditionalInput_t additionalInputs[],
    uint32_t numberOfInputs,
    uint8_t * pOut,
    uint32_t * const pOutLength
    );


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_ECDH_INTERNAL_H_ */
