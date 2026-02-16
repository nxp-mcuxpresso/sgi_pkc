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

/** @file  mcuxClHashModes_Internal_nonBlocking.h
 *  @brief Internal declarations for non blocking modes
 */

#ifndef MCUXCLHASHMODES_INTERNAL_NONBLOCKING_H_
#define MCUXCLHASHMODES_INTERNAL_NONBLOCKING_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClBuffer.h>
#include <internal/mcuxClHash_Internal.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mcuxClHash_Sha2_Oneshot_Internal_IsrCtx
{
    mcuxCl_InputBuffer_t inputBuf;
    uint32_t inSize;
    uint32_t numberOfFullBlocks;
    mcuxCl_Buffer_t pOut;
    uint32_t *pOutSize;
    mcuxClHash_AlgorithmDescriptor_t * algorithm;
} mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t;


typedef struct mcuxClHash_Sha2_Multipart_Internal_IsrCtx
{
    mcuxCl_InputBuffer_t inputBuf;
    uint32_t inputOffset;
    uint32_t inSize;
    uint32_t numberOfFullBlocks;
    mcuxClHash_ContextDescriptor_t *ctx;
} mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t;


#define MCUXCLHASHMODES_INTERNAL_SHA2_ISR_CTX_SIZE_IN_WORDS MCUXCLCORE_MAX(MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t)), MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t)))

#define MCUXCLHASHMODES_INTERNAL_SHA2_ISR_CTX_SIZE (MCUXCLHASHMODES_INTERNAL_SHA2_ISR_CTX_SIZE_IN_WORDS * sizeof(uint32_t))

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLHASHMODES_INTERNAL_NONBLOCKING_H_ */
