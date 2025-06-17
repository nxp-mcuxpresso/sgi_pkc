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

/** @file  mcuxClHmac_Internal_Functions.h
 *  @brief Internal definitions of helper functions for the HMAC component
 */

#ifndef MCUXCLHMAC_INTERNAL_FUNCTIONS_H_
#define MCUXCLHMAC_INTERNAL_FUNCTIONS_H_

#include <mcuxCsslFlowProtection.h>
#include <mcuxClBuffer.h>
#include <mcuxClMac_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSession_Types.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClHmac_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/****************************/
/* ExitGate functions       */
/****************************/

/**
 * @brief Exit gate function for abnormal and OK returns.
 *
 * This function securely clears a given memory area and also frees the cpuWa.
 *
 * @param session                   Current CL session
 * @param pMemoryToClear            Pointer to sensitive data to be securely cleared
 * @param wordSizeMemoryToClear     Size of pMemoryToClear
 * @param wordSizeCpuWaBuffer       cpuWa usage of the calling function
 *
 * @return @p statusCode
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHmac_cleanupOnExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_cleanupOnExit(
    mcuxClSession_Handle_t session,
    uint32_t *pMemoryToClear,
    size_t wordSizeMemoryToClear,
    size_t wordSizeCpuWaBuffer
);

/****************************/
/* Skeleton functions       */
/****************************/

/**
 * @brief HMAC Oneshot Compute function
 *
 * This function acts as an intermediate layer between the mcuxClMac_compute API and specific HMAC algorithm cores
 *
 * @param[in]  session      Handle for the current CL session.
 * @param[in]  key          Key to be used to authenticate the data.
 * @param[in]  mode         Mode that should be used during the MAC operation.
 * @param[in]  pIn          Input buffer that contains the data that needs to be authenticated.
 * @param[in]  inLength     Number of bytes of data in the @p pIn buffer.
 * @param[out] pMac         Output buffer where the MAC needs to be written.
 * @param[out] pMacLength   Will be incremented by the number of bytes of data that have been written to the @p pMac buffer.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHmac_compute, mcuxClMac_ComputeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClHmac_compute(
    mcuxClSession_Handle_t session,
    mcuxClKey_Handle_t key,
    mcuxClMac_Mode_t mode,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inLength,
    mcuxCl_Buffer_t pMac,
    uint32_t * const pMacLength
);


/**
 * @brief HMAC Multipart Init function
 *
 * This function acts as an intermediate layer between the mcuxClMac_init API and specific HMAC algorithm cores
 *
 * @param[in]  session   Handle for the current CL session.
 * @param[in]  pContext  MAC context which is used to maintain the state and
 *                       store other relevant information about the operation.
 * @param[in]  key       Key to be used to authenticate the data.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHmac_init, mcuxClMac_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_init(
    mcuxClSession_Handle_t session,
    mcuxClMac_Context_t * const pContext,
    mcuxClKey_Handle_t key
);

/**
 * @brief HMAC Multipart Process function
 *
 * This function acts as an intermediate layer between the mcuxClMac_process API and specific HMAC algorithm cores
 *
 * @param      session   Handle for the current CL session.
 * @param[in]  pContext  MAC context which is used to maintain the state and
 *                       store other relevant information about the operation.
 * @param[in]  pIn       Input buffer that contains the data that need to be processed.
 * @param[in]  inLength  Number of bytes of data in the @p pIn buffer.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHmac_process, mcuxClMac_ProcessFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClHmac_process(
    mcuxClSession_Handle_t session,
    mcuxClMac_Context_t * const pContext,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inLength
);

/**
 * @brief HMAC Multipart Finish function
 *
 * This function acts as an intermediate layer between the mcuxClMac_finish API and specific HMAC algorithm cores
 *
 * @param[in]  session     Handle for the current CL session.
 * @param[in]  pContext    MAC context which is used to maintain the state and
 *                         store other relevant information about the operation.
 * @param[out] pMac        Output buffer where the MAC needs to be written.
 * @param[out] pMacLength  Will be incremented by the number of bytes of data that
 *                         have been written to the @p pMac buffer.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHmac_finish, mcuxClMac_FinishFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_finish(
    mcuxClSession_Handle_t session,
    mcuxClMac_Context_t * const pContext,
    mcuxCl_Buffer_t pMac,
    uint32_t * const pMacLength
);



#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLHMAC_INTERNAL_FUNCTIONS_H_ */
