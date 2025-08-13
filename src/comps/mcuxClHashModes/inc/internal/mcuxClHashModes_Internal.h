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

/** @file  mcuxClHashModes_Internal.h
 *  @brief Definitions and declarations of the *INTERNAL* layer of the
 *         @ref mcuxClHashModes component
 */

#ifndef MCUXCLHASHMODES_INTERNAL_H_
#define MCUXCLHASHMODES_INTERNAL_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClHash_Types.h>
#include <mcuxClToolchain.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal_Memory.h>
#include <internal/mcuxClHashModes_Internal_sgi_sha2.h>
#include <internal/mcuxClSgi_Utils.h>
#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * CONSTANTS
 **********************************************/


#define MCUXCLHASHMODES_SHAKE_PHASE_INIT       (0x00000000u) /* Initialization phase of Shake: buffer will be cleared */
#define MCUXCLHASHMODES_SHAKE_PHASE_ABSORB     (0x0F0F0F0Fu) /* Absorb phase of Shake: don't clear any more, but also don't add padding yet */
#define MCUXCLHASHMODES_SHAKE_PHASE_SQUEEZE    (0xF0F0F0F0u) /* Squeeze phase of Shake: padding has been added, from now on only permute on the state */

/**********************************************
 * Type declarations
 **********************************************/

/**
 * @brief Internal Hash Algorithm structure
 *
 */
typedef struct mcuxClHashModes_Internal_AlgorithmDescriptor
{
  mcuxClSgi_Utils_initHash sgiUtilsInitHash;
  uint32_t protectionToken_sgiUtilsInitHash;
  mcuxClSgi_Utils_loadInternalHashBlock sgiLoadInternalDataBlock;
  uint32_t protectionToken_sgiLoadInternalDataBlock;
  uint32_t dummyValue;                                          ///< needed in the absense of any algorithm using internal algorithm properties
} mcuxClHashModes_Internal_AlgorithmDescriptor_t;
/**@}*/

/**********************************************
 * Function declarations
 **********************************************/

#define MCUXCLHASHMODES_SWITCH_4BYTE_ENDIANNESS(val)   \
        ((((val) & 0xFFu)       << 24)   \
        | (((val) & 0xFF00u)     << 8)   \
        | (((val) & 0xFF0000u)   >> 8)   \
        | (((val) & 0xFF000000u) >> 24))   ///< Macro to switch the endianness of a CPU word

#define MCUXCLHASHMODES_SWITCH_8BYTE_ENDIANNESS(val)      \
         ((((val) << 56u) & 0xFF00000000000000u) |  \
          (((val) << 40u) & 0x00FF000000000000u) |  \
          (((val) << 24u) & 0x0000FF0000000000u) |  \
          (((val) << 8u ) & 0x000000FF00000000u) |  \
          (((val) >> 8u ) & 0x00000000FF000000u) |  \
          (((val) >> 24u) & 0x0000000000FF0000u) |  \
          (((val) >> 40u) & 0x000000000000FF00u) |  \
          (((val) >> 56u) & 0x00000000000000FFu))







/** Inline function to convert word-aligned pointer to specific context. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_castPointerToContext)
static inline mcuxClHash_Context_t mcuxClHashModes_castPointerToContext(uint32_t *pContext)
{
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClHash_Context_t pCtx = (mcuxClHash_Context_t)pContext;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    return pCtx;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLHASHMODES_INTERNAL_H_ */
