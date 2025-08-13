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
 * @file  mcuxClEcc_EdDSA_Internal_InputParamSanityCheck.c
 * @brief Functions to perform sanity checks for input parameters of EdDSA API functions
 */


#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClSession_Internal.h>


/**
 * This function performs basic checks of private and public key handles privKey resp. pubKey passed to an EdDSA API function. It checks:
 *  - if the key handles are for EdDSA usage
 *  - if the key handles belong to the same curve (Ed25519 or Ed448)
 *  - if privKey is a private key handle
 *  - if pubKey is a public key handle
 *
 * Input:
 *  - privKey [in]  private key handle
 *  - pubKey [in]   public key handle
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_KeyPairSanityCheck)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_EdDSA_KeyPairSanityCheck(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t privKey,
    mcuxClKey_Handle_t pubKey)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_KeyPairSanityCheck);

    if((MCUXCLKEY_ALGO_ID_ECC_EDDSA != mcuxClKey_getAlgorithm(privKey))
                || (MCUXCLKEY_ALGO_ID_ECC_EDDSA != mcuxClKey_getAlgorithm(pubKey))
                || (mcuxClKey_getTypeInfo(privKey) != mcuxClKey_getTypeInfo(pubKey))
                || (MCUXCLKEY_ALGO_ID_PRIVATE_KEY != mcuxClKey_getKeyUsage(privKey))
                || (MCUXCLKEY_ALGO_ID_PUBLIC_KEY != mcuxClKey_getKeyUsage(pubKey)))
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_INVALID_PARAMS);
    }
    else
    {
        MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_EdDSA_KeyPairSanityCheck);
    }
}
