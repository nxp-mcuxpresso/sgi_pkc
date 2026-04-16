/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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

/** @file  mcuxClKey_Derivation.c
 *  @brief Implementation of Key Derivation engines */

#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>

#include <mcuxCsslFlowProtection.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxCsslAnalysis.h>

#ifdef MCUXCL_FEATURE_KEY_DERIVATION
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_derivationKey_variableLength =
{
    .algoId = MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY,
    .size = 0u,
    .info = NULL,
    .plainEncoding = &mcuxClKey_EncodingDescriptor_Plain
};

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_derivation)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_derivation(
    mcuxClSession_Handle_t session,
    mcuxClKey_Derivation_t derivationMode,
    mcuxClKey_Handle_t derivationKey,
    mcuxClKey_DerivationInput_t inputs[],
    uint32_t numberOfInputs,
    mcuxClKey_Handle_t derivedKey
)
{
    MCUXCLSESSION_ENTRY(session, mcuxClKey_derivation, diRefValue, MCUXCLKEY_STATUS_FAULT_ATTACK, derivationMode->derivationAlgorithm->protectionTokenDerivationEngine);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(derivationMode->derivationAlgorithm->pDerivationEngine(
        session,
        derivationMode,
        derivationKey,
        inputs,
        numberOfInputs,
        derivedKey));

    MCUXCLSESSION_EXIT(session, mcuxClKey_derivation, diRefValue, MCUXCLKEY_STATUS_OK, MCUXCLKEY_STATUS_FAULT_ATTACK);
}

#endif /* MCUXCL_FEATURE_KEY_DERIVATION */