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

#ifndef MCUXCLHASHMODES_MODESMEMORYMACROS_H
#define MCUXCLHASHMODES_MODESMEMORYMACROS_H

#include <internal/mcuxClHashModes_ModesMemoryMacros_Impl.h>

/** @brief Returns a struct initialization (mcuxClHash_AlgorithmDescriptor_t) of a hash mode.
 *         The members for the descriptor are defined in mcuxClHashModes_ModesConstants.h.
 *
 *  @param  DESCRIPTOR            Name of the descriptor. Defined in mcuxClHashModes_ModesConstants.h.
 *  @param  ALGORITHM_DETAILS     Pointer to the internal algorithm descriptor (mcuxClHashModes_Internal_AlgorithmDescriptor_t).
 *                                Can be NULL. The internal algorithm descriptor is initialized directly without a macro.
 */
#define MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR(DESCRIPTOR, ALGORITHM_DETAILS) \
  MCUXCLHASHMODES_MAKE_ALGORITHM_DESCRIPTOR_IMPL(DESCRIPTOR, ALGORITHM_DETAILS)

/** @brief Returns the memory consumption of the oneshot skeleton of a given descriptor. Given two descriptors as
 *         parameters, it returns the maximum of these two.  */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_ONESHOT(...) \
  MCUXCLHASHMODES_COMPUTE_MEMORY_ONESHOT_IMPL(__VA_ARGS__)


/** @brief Returns the memory consumption of the process skeleton of a given descriptor. Given two descriptors as
 *         parameters, it returns the maximum of these two.  */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_PROCESS(...) \
  MCUXCLHASHMODES_COMPUTE_MEMORY_PROCESS_IMPL(__VA_ARGS__)

/** @brief Returns the memory consumption of the finish skeleton of a given descriptor. Given two descriptors as
 *         parameters, it returns the maximum of these two.  */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_FINISH(...) \
  MCUXCLHASHMODES_COMPUTE_MEMORY_FINISH_IMPL(__VA_ARGS__)

/** @brief Returns the maximum memory consumption for @p DESCRIPTOR:
 *         MAX(oneshot, process, finish) or 4 if the mode is not active.
 */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_MAX(DESCRIPTOR) \
  MCUXCLCORE_MAX( \
    MCUXCLHASHMODES_COMPUTE_MEMORY_ONESHOT(DESCRIPTOR), \
    MCUXCLCORE_MAX(MCUXCLHASHMODES_COMPUTE_MEMORY_PROCESS(DESCRIPTOR), MCUXCLHASHMODES_COMPUTE_MEMORY_FINISH(DESCRIPTOR)) \
  )

/** @brief Returns the context memory size consumption of for a given descriptor. Given two descriptors as
 *         parameters, it returns the maximum context size of these two.
 */
#define MCUXCLHASHMODES_COMPUTE_MEMORY_CONTEXT(...) \
  MCUXCLHASHMODES_COMPUTE_MEMORY_CONTEXT_IMPL(__VA_ARGS__)

#endif /* MCUXCLHASHMODES_MODESMEMORYMACROS_H */
