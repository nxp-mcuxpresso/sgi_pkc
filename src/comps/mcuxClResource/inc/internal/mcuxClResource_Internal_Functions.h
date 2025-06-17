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
 * @file  mcuxClResource_Internal_Functions.h
 * @brief Internal functions of the mcuxClResource component
 */

#ifndef MCUXCLRESOURCE_INTERNAL_FUNCTIONS_H_
#define MCUXCLRESOURCE_INTERNAL_FUNCTIONS_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClSession_Types.h>
#include <mcuxClResource_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Request hardware
 *
 * @param session                        Handle for the CL session requesting Hw.
 * @param hwId                           HW to be requested.
 * @param option                         Option for requesting HW.
 * @param pHwIrqHandler                  Function pointer handling HW interrupt.
 * @param protectionToken_pHwIrqHandler  Protection token of the HW interrupt handler.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClResource_request)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClResource_request(
    mcuxClSession_Handle_t session,
    mcuxClResource_HwId_t hwId,
    mcuxClResource_HwStatus_t option,
    mcuxClSession_HwInterruptHandler_t pHwIrqHandler,
    uint32_t protectionToken_pHwIrqHandler
);

/**
 * @brief Release hardware
 *
 * @param pResourceCtx  Global resource context.
 * @param hwId          HW to be released.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClResource_release)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClResource_release(
    mcuxClResource_Context_t * pResourceCtx,
    mcuxClResource_HwId_t hwId
);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLRESOURCE_INTERNAL_FUNCTIONS_H_ */
