/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/** @file  mcuxClXofModes_Internal_Memory.h
 *  @brief Internal memory consumption definitions of the mcuxClXofModes component
 */

#ifndef MCUXCLXOFMODES_INTERNAL_MEMORY_H_
#define MCUXCLXOFMODES_INTERNAL_MEMORY_H_

#include <internal/mcuxClHashModes_Internal_Memory.h>
#include <internal/mcuxClXof_Internal.h>

/* CPU WA size for the Xof Shake */
#if defined(MCUXCL_FEATURE_XOF_C_SHAKE_128) || defined(MCUXCL_FEATURE_XOF_C_SHAKE_256)
#define MCUXCLXOF_INTERNAL_WACPU_SIZE_C_SHAKE        MCUXCLCORE_MAX (MCUXCLCORE_MAX(MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3_ONESHOT, \
                                                                    MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3_PROCESS), \
                                                                MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3_FINISH)
#else
#define MCUXCLXOF_INTERNAL_WACPU_SIZE_C_SHAKE (4u)
#endif /* defined(MCUXCL_FEATURE_XOF_C_SHAKE_128) || defined(MCUXCL_FEATURE_XOF_C_SHAKE_256) */

#define MCUXCLXOF_INTERNAL_WACPU_SIZE_LTC_SHAKE (4u)

#define MCUXCLXOF_INTERNAL_WACPU_SIZE_SECSHAKE (4u)

#define MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE   (MCUXCLCORE_MAX(MCUXCLXOF_INTERNAL_WACPU_SIZE_C_SHAKE,       \
                                              MCUXCLCORE_MAX(MCUXCLXOF_INTERNAL_WACPU_SIZE_LTC_SHAKE,       \
                                                            MCUXCLXOF_INTERNAL_WACPU_SIZE_SECSHAKE)))

/* Context size */
#if defined(MCUXCL_FEATURE_XOF_C_SHAKE_128)
#define MCUXCLXOFMODES_SHAKE128_CONTEXT_SIZE_INTERNAL (sizeof(mcuxClXof_ContextDescriptor_t) + MCUXCLHASHMODES_SHAKE128_CONTEXT_SIZE_INTERNAL)
#else
#define MCUXCLXOFMODES_SHAKE128_CONTEXT_SIZE_INTERNAL (4u)
#endif /* defined(MCUXCL_FEATURE_XOF_C_SHAKE_128) || defined(MCUXCL_FEATURE_XOF_LTC_SHAKE_128) */

#if defined(MCUXCL_FEATURE_XOF_C_SHAKE_256)
#define MCUXCLXOFMODES_SHAKE256_CONTEXT_SIZE_INTERNAL (sizeof(mcuxClXof_ContextDescriptor_t) + MCUXCLHASHMODES_SHAKE256_CONTEXT_SIZE_INTERNAL)
#else
#define MCUXCLXOFMODES_SHAKE256_CONTEXT_SIZE_INTERNAL (4u)
#endif /* defined(MCUXCL_FEATURE_XOF_C_SHAKE_256) || defined(MCUXCL_FEATURE_XOF_LTC_SHAKE_256) */

#define MCUXCLXOFMODES_SECSHAKE128_CONTEXT_SIZE_INTERNAL (4u)

#define MCUXCLXOFMODES_SECSHAKE256_CONTEXT_SIZE_INTERNAL (4u)

#define MCUXCLXOFMODES_CONTEXT_MAX_SIZE_INTERNAL                                                   \
                  MCUX_CSSL_ANALYSIS_START_PATTERN_INVARIANT_EXPRESSION_WORKAREA_CALCULATIONS()    \
                  (MCUXCLCORE_MAX(MCUXCLXOFMODES_SHAKE128_CONTEXT_SIZE_INTERNAL,                    \
                   MCUXCLCORE_MAX(MCUXCLXOFMODES_SHAKE256_CONTEXT_SIZE_INTERNAL,                    \
                   MCUXCLCORE_MAX(MCUXCLXOFMODES_SECSHAKE128_CONTEXT_SIZE_INTERNAL,                 \
                                MCUXCLXOFMODES_SECSHAKE256_CONTEXT_SIZE_INTERNAL))))               \
                  MCUX_CSSL_ANALYSIS_STOP_PATTERN_INVARIANT_EXPRESSION_WORKAREA_CALCULATIONS()

#endif /* MCUXCLXOFMODES_INTERNAL_MEMORY_H_ */
