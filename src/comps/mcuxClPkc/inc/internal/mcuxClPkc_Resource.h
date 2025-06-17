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

/**
 * @file  mcuxClPkc_Resource.h
 * @brief Macros for requesting/releasing PKC
 */


#ifndef MCUXCLPKC_RESOURCE_H_
#define MCUXCLPKC_RESOURCE_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClSession.h>
#include <internal/mcuxClPkc_Internal_Types.h>
#include <internal/mcuxClPkc_Internal_Functions.h>

#include <mcuxClResource_Types.h>
#include <internal/mcuxClResource_Internal_Types.h>
#include <internal/mcuxClSession_Internal_Functions.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Macro to request PKC resource and initialize PKC. */
#define MCUXCLPKC_FP_REQUEST_INITIALIZE(session, callerName) \
    do {  \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID( \
            mcuxClResource_request(session, MCUXCLRESOURCE_HWID_PKC, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE, NULL, 0U) \
        ); \
        MCUXCLPKC_FP_INITIALIZE(session); \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION() \
    } while (false) \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()

/** Macro to deinitialize PKC and release PKC resource */
#define MCUXCLPKC_FP_DEINITIALIZE_RELEASE(session) \
    do {  \
        MCUXCLPKC_FP_DEINITIALIZE();\
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_release(session->pResourceCtx, MCUXCLRESOURCE_HWID_PKC)); \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION() \
    } while (false) \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()

#define MCUXCLPKC_FP_CALLED_REQUEST_INITIALIZE \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_request), \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Initialize)


#define MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize),\
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_release)


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLPKC_RESOURCE_H_ */
