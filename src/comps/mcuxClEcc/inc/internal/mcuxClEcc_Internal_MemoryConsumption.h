/*--------------------------------------------------------------------------*/
/* Copyright 2025-2026 NXP                                                  */
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

/** @file  mcuxClEcc_Internal_MemoryConsumption.h
 *  @brief Internal memory consumption definitions of the mcuxClEcc component */

#ifndef MCUXCLECC_INTERNAL_MEMORY_CONSUMPTION_H_
#define MCUXCLECC_INTERNAL_MEMORY_CONSUMPTION_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClCore_Macros.h>

/* mcuxClMath_Internal.h provides MCUXCLMATH_SIZEOF_MATH_UPTRT which is used in PKC operations */
#include <internal/mcuxClMath_Internal.h>


#ifdef __cplusplus
extern "C" {
#endif


/****************************************************************************/
/* Macros for workarea sizes for mcuxClEcc_InitializeEnvironment.            */
/****************************************************************************/
#define SIZEOF_ECC_UPTRT_WA(NO_BUFFERS, NO_VIRTUALS)    (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(sizeof(uint16_t) * ((NO_BUFFERS) + (NO_VIRTUALS))))
/* Size of ECC UPTRT workarea for specified number of buffers and virtual pointers */
#define SIZEOF_TOTAL_UPTRT_WA(NO_BUFFERS, NO_VIRTUALS)  (MCUXCLMATH_SIZEOF_MATH_UPTRT + SIZEOF_ECC_UPTRT_WA(NO_BUFFERS, NO_VIRTUALS))
/* Total size of UPTRT workarea including Math and ECC components */

#define SIZEOF_ECCCPUWA_T                           (MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_CpuWa_t)) + sizeof(uint32_t)) /* Reserve 1 word for making UPTR table start from 64-bit aligned address */
/* Size of ECC CPU workarea structure with extra word for 64-bit alignment */
#define MCUXCLECC_SIZEOF_UPTRT_CPUWA(NO_BUFFERS, NO_VIRTUALS) SIZEOF_TOTAL_UPTRT_WA(NO_BUFFERS, NO_VIRTUALS)
/* Size of UPTRT in CPU workarea when UPTRT is stored in CPU RAM */
#define MCUXCLECC_SIZEOF_UPTRT_PKCWA(NO_BUFFERS, NO_VIRTUALS) 0U
/* Size of UPTRT in PKC workarea when UPTRT is stored in CPU RAM */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_INTERNAL_MEMORY_CONSUMPTION_H_ */
