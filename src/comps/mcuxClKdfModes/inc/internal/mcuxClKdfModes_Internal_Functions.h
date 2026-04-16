/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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

/**
 * @file  mcuxClKdfModes_Internal_Functions.h
 * @brief Internal function definitions for the mcuxClKdfModes component
 */

#ifndef MCUXCLKDFMODES_INTERNAL_FUNCTIONS_H_
#define MCUXCLKDFMODES_INTERNAL_FUNCTIONS_H_

#ifdef __cplusplus
extern "C" {
#endif

/** Inline function to convert word-aligned pointer to specific CPU workarea. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKdfModes_castPointerToCpuWa)
static inline mcuxClKdfModes_WorkArea_t* mcuxClKdfModes_castPointerToCpuWa(uint32_t *pCpuWa32BitAligned)
{
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKdfModes_WorkArea_t* pCpuWa = (mcuxClKdfModes_WorkArea_t*)pCpuWa32BitAligned;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    return pCpuWa;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKDFMODES_INTERNAL_FUNCTIONS_H_ */
