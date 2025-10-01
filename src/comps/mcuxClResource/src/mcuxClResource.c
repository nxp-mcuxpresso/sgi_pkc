/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @file  mcuxClResource.c
 * @brief Implementation of the mcuxClResource component
 */

#include <platform_specific_headers.h>
#include <mcuxClToolchain.h>
#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxClSgi_Constants.h>
#include <mcuxClResource.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClResource_Internal_Types.h>
#include <internal/mcuxClResource_Internal_Functions.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClResource_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClResource_Status_t) mcuxClResource_init(
    mcuxClResource_Context_t * pResourceCtx,
    mcuxClResource_MutexAcquire_Callback_t pMutexAcquire UNUSED_PARAM,
    mcuxClResource_MutexRelease_Callback_t pMutexRelease UNUSED_PARAM
    )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClResource_init);

    for(uint32_t i = 0u; i < MCUXCLRESOURCE_HWID_TOTAL; i++)
    {
        pResourceCtx->hwTable[i].status = MCUXCLRESOURCE_HWSTATUS_AVAILABLE;
        pResourceCtx->hwTable[i].session = NULL;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClResource_init, MCUXCLRESOURCE_STATUS_OK, MCUXCLRESOURCE_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClResource_handle_interrupt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClResource_Status_t) mcuxClResource_handle_interrupt(
  const mcuxClResource_Context_t* pResourceCtx,
  mcuxClResource_Interrupt_t interrupt
)
{
    mcuxClResource_HwId_t hwId = MCUXCLRESOURCE_HWID_IRQ(interrupt);

    if(MCUXCLRESOURCE_HWID_INVALID == hwId)
    {
        /* If there is no proper hwId/session, perform a simple FUNCTION_ENTRY+FUNCTION_EXIT */
        MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClResource_handle_interrupt);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClResource_handle_interrupt, MCUXCLRESOURCE_STATUS_ERROR);
    }

    mcuxClSession_Handle_t session = pResourceCtx->hwTable[hwId].session;

    /* We have a proper session associated to the HW:
         *   - wrap-up the CLib operation for which the interrupt was triggered
         *   - use SESSION_ENTRY/SESSION_EXIT to make use of the early-exit strategy internally */
    MCUXCLSESSION_ENTRY(session, mcuxClResource_handle_interrupt, diRefValue, MCUXCLRESOURCE_STATUS_FAULT_ATTACK);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(session->jobContext.pCallBackDMA(session));

    MCUXCLSESSION_EXIT(
      session,
      mcuxClResource_handle_interrupt,
      diRefValue,
      MCUXCLRESOURCE_STATUS_OK,
      MCUXCLRESOURCE_STATUS_FAULT_ATTACK,
      session->jobContext.protectionToken_pCallBackDMA
    );
}

/**
 * [DESIGN]
 * This function will be called either directly when initializing HW in a single session,
 * or by Resource_restore in case of context switching.
 * When called directly, option shall contain only one HwStatus.
 * When called by Resource_restore, option might contain multiple HwStatus.
 *
 * In case a session has owned a HW and requests it again (only via direct call),
 * the multi-request is handled by left-shifting the word hwTable[HW].status and
 * storing the new option (HwStatus) in LSBits.
 * When releasing a HW, the word hwTable[HW].status is right-shifted to remove
 * the latest option. Once the status word is 0 (HWSTATUS_AVAILABLE), the HW
 * will be removed from the Session.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClResource_request)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClResource_request(
  mcuxClSession_Handle_t session,
  mcuxClResource_HwId_t hwId,
  mcuxClResource_HwStatus_t option,
  mcuxClSession_HwInterruptHandler_t pHwIrqHandler,
  uint32_t protectionToken_pHwIrqHandler
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClResource_request);

    if(MCUXCLRESOURCE_HWID_TOTAL <= hwId)
    {
        MCUXCLSESSION_ERROR(session, MCUXCLRESOURCE_STATUS_ERROR);
    }

    mcuxClResource_Context_t* pResourceCtx = session->pResourceCtx;
    mcuxClResource_hwAllocation_t* hw = &pResourceCtx->hwTable[hwId];
    mcuxClResource_HwStatus_t status = hw->status;

    if(MCUXCLRESOURCE_HWSTATUS_AVAILABLE == status)
    {
        hw->status = option;
        hw->session = session;
    }
    /* HW has been assigned to the current session. */
    /* This case shall be only triggered by Session_request, i.e., option only contains one HwStatus. */
    else if(hw->session == session)
    {
        /* Check if there is space to store one new request option. */
        if(MCUXCLRESOURCE_HWSTATUS_AVAILABLE == (status >> (32u - MCUXCLRESOURCE_HWSTATUS_SIZE_IN_BITS)))
        {
            /* Left-shift the original status, and keep the new option in LSBits of status. */
            hw->status = (status << MCUXCLRESOURCE_HWSTATUS_SIZE_IN_BITS) | option;
        }
    }
    else
    {
        MCUXCLSESSION_ERROR(session, MCUXCLRESOURCE_STATUS_UNAVAILABLE);
    }

    if(NULL != pHwIrqHandler)
    {
        session->jobContext.pCallBackDMA = pHwIrqHandler;
        session->jobContext.protectionToken_pCallBackDMA = protectionToken_pHwIrqHandler;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClResource_request);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClResource_release)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClResource_release(
    mcuxClResource_Context_t * pResourceCtx,
    mcuxClResource_HwId_t hwId
    )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClResource_release);

    mcuxClResource_hwAllocation_t * hw = & pResourceCtx->hwTable[hwId];
    mcuxClResource_HwStatus_t status = hw->status;

    /* Remove the latest HwStatus from the status word. */
    status >>= MCUXCLRESOURCE_HWSTATUS_SIZE_IN_BITS;
    hw->status = status;

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClResource_release);
}

