/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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

/** @file  mcuxClHashModes_Internal_sgi_sha2.h
 *  @brief Internal definitions and declarations of the *INTERNAL* layer dedicated to SGI
 */

#ifndef MCUXCLHASHMODES_INTERNAL_SGI_SHA2_H_
#define MCUXCLHASHMODES_INTERNAL_SGI_SHA2_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MCUXCLHASHMODES_INTERNAL_SGI_SHA2_FIRST_SGI_OP (0xa5a5u)
#define MCUXCLHASHMODES_INTERNAL_SGI_SHA2_SUBSEQUENT_SGI_OP (0x5a5au)

#define MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE         (0xFFFFu)
#define MCUXCLHASHMODES_INTERNAL_SGI_COUNT_MAX_VALUE_IN_LOOP (0xFFFEu)

/**
 * @brief Oneshot Skeleton implementation for Sha2 with SGI support
 *
 * Data Integrity: Expunge(pIn + inSize + pOut + pOutSize)
 *
 * @note Function uses early-exit mechanism with following return codes:
 *       - MCUXCLHASH_STATUS_FAILURE - If the hash counter value is different from the expected value or
            if there's a failure when copying hash digest to output buffer.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHashModes_Sgi_oneShot_Sha2, mcuxClHash_AlgoSkeleton_OneShot_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_Sgi_oneShot_Sha2(mcuxClSession_Handle_t session,
                                                   mcuxClHash_Algo_t algorithm,
                                                   mcuxCl_InputBuffer_t pIn,
                                                   uint32_t inSize,
                                                   mcuxCl_Buffer_t pOut,
                                                   uint32_t *const pOutSize);

/**
 * @brief Process Skeleton implementation for Sha2 with SGI support
 *
 * Data Integrity: Expunge(context + pIn + inSize)
 *
 * @note Function uses early-exit mechanism with following return codes:
 *       - MCUXCLHASH_STATUS_FULL - when the total input size exceeds the upper limit.
 *       - MCUXCLHASH_STATUS_FAILURE - If the hash counter value is different from the expected value.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHashModes_Sgi_process_Sha2, mcuxClHash_AlgoSkeleton_Process_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_Sgi_process_Sha2(mcuxClSession_Handle_t session UNUSED_PARAM,
                                                   mcuxClHash_Context_t context,
                                                   mcuxCl_InputBuffer_t pIn,
                                                   uint32_t inSize);

/**
 * @brief Finish Skeleton implementation for Sha2 with SGI support
 *
 * Data Integrity: Expunge(context + pOut + pOutSize)
 *
 * @note Function uses early-exit mechanism with following return codes:
 *       - MCUXCLHASH_STATUS_FULL - when the total input size exceeds the upper limit.
 *       - MCUXCLHASH_STATUS_FAULT_ATTACK - if the context->unprocessedLength exceeds the upper limit.
 *       - MCUXCLHASH_STATUS_FAILURE - If the hash counter value is different from the expected value or
 *                                       if there's a failure when copying hash digest to output buffer.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHashModes_Sgi_finish_Sha2, mcuxClHash_AlgoSkeleton_Finish_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_Sgi_finish_Sha2(mcuxClSession_Handle_t session UNUSED_PARAM,
                                                  mcuxClHash_Context_t context,
                                                  mcuxCl_Buffer_t pOut,
                                                  uint32_t *const pOutSize);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLHASHMODES_INTERNAL_SGI_SHA2_H_ */
