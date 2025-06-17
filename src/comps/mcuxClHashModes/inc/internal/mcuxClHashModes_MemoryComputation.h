/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

#ifndef MCUXCL_HASHMODES_MEMORYCOMPUTATION_H
#define MCUXCL_HASHMODES_MEMORYCOMPUTATION_H

#include <mcuxClCore_Macros.h>
#include <internal/mcuxClHashModes_ModesConstants.h>
#include <internal/mcuxClHashModes_ModesMemoryMacros.h>
#include <mcuxCsslCPreProcessor.h>

/**
 * Please define memory computation macros for a family of modes here.
 */


/*
 * C_SHA-1 mode
 */

/** @brief Memory consumption of C_SHA-1 oneshot */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_C_SHA1_ONESHOT(DESCRIPTOR) \
    ( ( MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLHASHMODES_GET_BLOCKSIZE(DESCRIPTOR)) \
    + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLHASHMODES_GET_STATESIZE(DESCRIPTOR)) ) * sizeof(uint32_t) )

/** @brief Memory consumption of C_SHA-1 process */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_C_SHA1_PROCESS(DESCRIPTOR)    4U

/** @brief Memory consumption of C_SHA-1 finish */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_C_SHA1_FINISH(DESCRIPTOR)     4U


/*
 * C_SHA-2 Modes
 */

/** @brief Memory consumption of C_SHA-2 oneshot */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_C_SHA2_ONESHOT(DESCRIPTOR) \
    ( ( ( (sizeof(uint32_t) + MCUXCLCORE_ALIGN_TO_WORDSIZE(sizeof(uint64_t), MCUXCLHASHMODES_GET_STATESIZE(DESCRIPTOR)) ) / sizeof(uint32_t) ) \
    + ( (sizeof(uint32_t) + MCUXCLCORE_ALIGN_TO_WORDSIZE(sizeof(uint64_t), MCUXCLHASHMODES_GET_BLOCKSIZE(DESCRIPTOR))) / sizeof(uint32_t) ) ) * sizeof(uint32_t))

/** @brief Memory consumption of C_SHA-2 process */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_C_SHA2_PROCESS(DESCRIPTOR)    4U

/** @brief Memory consumption of C_SHA-2 finish */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_C_SHA2_FINISH(DESCRIPTOR)     4U

/*
 * SHA-2 SGI Normal Modes
 */

/** @brief Memory consumption of SGI SHA-2 oneshot */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_SGI_SHA2_ONESHOT(DESCRIPTOR) \
    (MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLHASHMODES_GET_BLOCKSIZE(DESCRIPTOR)) * sizeof(uint32_t))

/** @brief Memory consumption of SGI SHA-2 process */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_SGI_SHA2_PROCESS(DESCRIPTOR)      4U

/** @brief Memory consumption of SGI SHA-2 finish */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_SGI_SHA2_FINISH(DESCRIPTOR)       4U

/*
 * SHA-2 SGI Non-Blocking Modes
 */

/** @brief Memory consumption of SGI SHA-2 non-blocking oneshot */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_NONBLOCKING_SHA2_ONESHOT(DESCRIPTOR) \
    ( ( MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClHash_Sha2_Oneshot_Internal_IsrCtx_t)) \
    + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLHASHMODES_GET_BLOCKSIZE(DESCRIPTOR)) ) * sizeof(uint32_t))

/** @brief Memory consumption of SGI SHA-2 non-blocking process */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_NONBLOCKING_SHA2_PROCESS(DESCRIPTOR) \
    ( MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClHash_Sha2_Multipart_Internal_IsrCtx_t)) * sizeof(uint32_t) )

/** @brief Memory consumption of SGI SHA-2 non-blocking finish */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_NONBLOCKING_SHA2_FINISH(DESCRIPTOR)       4U

#endif /* MCUXCL_HASHMODES_MEMORYCOMPUTATION_H */
