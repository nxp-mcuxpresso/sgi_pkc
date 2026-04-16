/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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

#include <mcuxClHash.h>
#include <internal/mcuxClHash_Internal.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslSecureCounter_Cfg.h>

#include <internal/mcuxClSession_Internal_EntryExit.h>

#ifdef MCUXCL_FEATURE_HASH_SELFTEST
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_selftest)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHash_selftest(
  mcuxClSession_Handle_t session,
  mcuxClHash_Algo_t algorithm,
  mcuxClHash_Test_t test
)
{
    MCUXCLSESSION_ENTRY(session, mcuxClHash_selftest, diRefValue, MCUXCLHASH_STATUS_FAULT_ATTACK);

    MCUX_CSSL_FP_FUNCTION_CALL(result, test->selftest(session, algorithm));

    MCUXCLSESSION_EXIT(session, mcuxClHash_selftest, diRefValue, result, MCUXCLHASH_STATUS_FAULT_ATTACK, test->protection_token_selftest);
}
#endif /* MCUXCL_FEATURE_HASH_SELFTEST */