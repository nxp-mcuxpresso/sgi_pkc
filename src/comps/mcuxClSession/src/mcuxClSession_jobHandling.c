/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023, 2025 NXP                                            */
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
 * @file  mcuxClSession_jobHandling.c
 * @brief mcuxClSession functions for job handling
 */

#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Platform.h>

#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClSession_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_configure_job)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_configure_job(
  mcuxClSession_Handle_t session,
  mcuxClSession_Channels_t dmaChannels,
  mcuxClSession_Callback_t pUserCallback,
  void* pUserData
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSession_configure_job);

    session->jobContext.dmaChannels = dmaChannels;
    session->jobContext.pUserCallback = pUserCallback;
    session->jobContext.pUserData = pUserData;

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClSession_configure_job, MCUXCLSESSION_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_triggerUserCallback)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_triggerUserCallback(
  mcuxClSession_Handle_t session,
  uint32_t status
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSession_triggerUserCallback);

    mcuxClSession_Callback_t pUserCallback = session->jobContext.pUserCallback;

    if(NULL == pUserCallback)
    {
        MCUXCLSESSION_ERROR(session, MCUXCLSESSION_STATUS_ERROR);
    }

    pUserCallback(status, session->jobContext.pUserData);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSession_triggerUserCallback, MCUXCLSESSION_STATUS_OK);
}
