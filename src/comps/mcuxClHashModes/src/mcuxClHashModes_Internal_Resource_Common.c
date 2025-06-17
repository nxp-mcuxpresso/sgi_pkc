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

#include <mcuxClToolchain.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClSession.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <internal/mcuxClDma_Utils_Sgi.h>
#include <internal/mcuxClDma_Drv.h>
#include <mcuxClDma_Types.h>
#include <internal/mcuxClDma_Resource.h>
#include <internal/mcuxClResource_Internal_Types.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal.h>
#include <internal/mcuxClHashModes_Internal_Resource_Common.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

/**********************************************************
 * Helper functions
 **********************************************************/

/**
 * @brief Hash modes LTC and SGI release function
 *
 * This function shall release LTC or SGI hardware based on releaseOption specified
 *
 * @param[in]       session                 Handle for the current CL session
 * @param[in]       releaseOption           Option indicating which hardware shall be released
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_LTC_SGI_Release)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_LTC_SGI_Release(
    mcuxClSession_Handle_t session,
    uint32_t releaseOption
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_LTC_SGI_Release);

    const uint32_t sgiOption = MCUXCLHASHMODES_REQ_SGI & releaseOption;

    if(MCUXCLHASHMODES_REQ_SGI == sgiOption)
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_release));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_release(session->pResourceCtx, MCUXCLRESOURCE_HWID_SGI));
    }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHashModes_LTC_SGI_Release);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_HwRequest)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_HwRequest(
    mcuxClSession_Handle_t session,
    mcuxClSession_HwInterruptHandler_t pHwIrqHandler,
    uint32_t protectionToken_pHwIrqHandler,
    uint32_t requestOption
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_HwRequest);

  const uint32_t sgiOption = MCUXCLHASHMODES_REQ_SGI & requestOption;

    if(MCUXCLHASHMODES_REQ_SGI == sgiOption)
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_request));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_request(
            session, MCUXCLRESOURCE_HWID_SGI,
            MCUXCLRESOURCE_HWSTATUS_NON_INTERRUPTABLE,
            NULL, 0U));
    }


  const uint32_t dmaInputOption   = MCUXCLHASHMODES_REQ_DMA_INPUT & requestOption;
  const uint32_t dmaOutputOption  = MCUXCLHASHMODES_REQ_DMA_OUTPUT & requestOption;

    mcuxClSession_HwInterruptHandler_t dmaIsr = NULL;
    uint32_t protectionToken_dmaIsr = 0U;
    if((NULL != pHwIrqHandler) && (MCUXCLHASHMODES_REQ_SGI == sgiOption))
    {
        dmaIsr = pHwIrqHandler;
        protectionToken_dmaIsr = protectionToken_pHwIrqHandler;
    }

    if ((MCUXCLHASHMODES_REQ_DMA_INPUT == dmaInputOption) && (MCUXCLHASHMODES_REQ_DMA_OUTPUT == dmaOutputOption))
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_requestInputAndOutput));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_requestInputAndOutput(session, dmaIsr, protectionToken_dmaIsr));
    }
    else
    {
        if(MCUXCLHASHMODES_REQ_DMA_INPUT == dmaInputOption)
        {
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_request));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_request(
                session,
                mcuxClSession_getDmaInputChannel(session),
                dmaIsr,
                protectionToken_dmaIsr));
        }

        if(MCUXCLHASHMODES_REQ_DMA_OUTPUT == dmaOutputOption)
        {
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_request));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_request(
                session,
                mcuxClSession_getDmaOutputChannel(session),
                dmaIsr,
                protectionToken_dmaIsr));
        }
    }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHashModes_HwRequest);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_HwRelease)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_HwRelease(
    mcuxClSession_Handle_t session,
    uint32_t releaseOption
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_HwRelease);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_LTC_SGI_Release));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClHashModes_LTC_SGI_Release(session, releaseOption));

    const uint32_t dmaInputOption = MCUXCLHASHMODES_REQ_DMA_INPUT & releaseOption;
    const uint32_t dmaOutputOption = MCUXCLHASHMODES_REQ_DMA_OUTPUT & releaseOption;

    if((MCUXCLHASHMODES_REQ_DMA_INPUT == dmaInputOption) && (MCUXCLHASHMODES_REQ_DMA_OUTPUT == dmaOutputOption))
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_releaseInputAndOutput));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_releaseInputAndOutput(session));
    }
    else
    {
        if(MCUXCLHASHMODES_REQ_DMA_INPUT == dmaInputOption)
        {
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_release));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_release(session, mcuxClSession_getDmaInputChannel(session)));
        }
        if(MCUXCLHASHMODES_REQ_DMA_OUTPUT == dmaOutputOption)
        {
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_release));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_release(session, mcuxClSession_getDmaOutputChannel(session)));
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHashModes_HwRelease);
}
