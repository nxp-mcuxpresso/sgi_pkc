/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

#ifndef MCUXCLDMA_RESOURCE_H_
#define MCUXCLDMA_RESOURCE_H_

#include <mcuxClDma_Types.h>
#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClSession_Types.h>
#include <mcuxClResource_Types.h>
#include <internal/mcuxClResource_Internal_Types.h>
#include <internal/mcuxClSession_Internal_Functions.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Request a DMA channel as NON_INTERRUPTABLE, install the callback function.
 *
 * @param session                           Session that requests the channel
 * @param channel                           Channel to be requested
 * @param callbackFunction                  Callback function to be written into the session job context
 * @param protectionToken_callbackFunction  Protection token of the callback function
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_request)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_request(
  mcuxClSession_Handle_t session,
  mcuxClSession_Channel_t channel,
  mcuxClSession_HwInterruptHandler_t callbackFunction,
  uint32_t protectionToken_callbackFunction
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClDma_request);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_request(
    session,
    MCUXCLRESOURCE_HWID_DMA(channel),
    MCUXCLRESOURCE_HWSTATUS_NON_INTERRUPTABLE,
    callbackFunction,
    protectionToken_callbackFunction
  ));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClDma_request,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_request));
}

/**
 * @brief Release a DMA channel
 *
 * @param session Session that releases the channel
 * @param channel Channel to be released
 *
 * @pre
 *  - @p channel has previously been requested by @p session
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_release)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_release(
  mcuxClSession_Handle_t session,
  mcuxClSession_Channel_t channel
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClDma_release);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(channel, 0u, DMA_CH_TOTAL-1u, MCUXCLRESOURCE_HWID_INVALID)
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_release(session->pResourceCtx, MCUXCLRESOURCE_HWID_DMA(channel)));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClDma_release, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_release));
}

/**
 * @brief Request DMA input and output channels as NON_INTERRUPTABLE
 *
 * @param session Session that requests the channels
 * @param callbackFunction Callback function to be written into the session job context
 * @param protectionToken_callbackFunction Protection token of the callback function
 *
 * @pre
 *  - Input and output might or might not map to the same DMA channel.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_requestInputAndOutput)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_requestInputAndOutput(
  mcuxClSession_Handle_t session,
  mcuxClSession_HwInterruptHandler_t callbackFunction,
  uint32_t protectionToken_callbackFunction
);

/**
 * @brief Release DMA input and output channels
 *
 * @param session Session that releases the channels
 *
 * @pre
 *  - Input and output might or might not map to the same DMA channel.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClDma_releaseInputAndOutput)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_releaseInputAndOutput(
  mcuxClSession_Handle_t session
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLDMA_RESOURCE_H_ */
