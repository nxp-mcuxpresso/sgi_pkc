/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2025 NXP                                                 */
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

/** @file  mcuxClKey_Validation.c
 *  @brief Implementation of Key Validation engines */

#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>

#include <mcuxCsslFlowProtection.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <internal/mcuxClSession_Internal_EntryExit.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_validate)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_validate(
    mcuxClSession_Handle_t session,
    mcuxClKey_Validation_t validation,
    mcuxClKey_Handle_t key
)
{
    MCUXCLSESSION_ENTRY(session, mcuxClKey_validate, diRefValue, MCUXCLKEY_STATUS_FAULT_ATTACK);

    MCUX_CSSL_FP_FUNCTION_CALL(result, validation->validateFct(session, key));

    MCUXCLSESSION_EXIT(session, mcuxClKey_validate, diRefValue, result, MCUXCLKEY_STATUS_FAULT_ATTACK,
        validation->validateFct_FP_FuncId);
}
