/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021, 2023-2026 NXP                                       */
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
 * @file  mcuxClMath_Internal.h
 * @brief Internal header of mcuxClMath component
 *
 * @defgroup mcuxClMath_Internal mcuxClMath_Internal
 * @brief component of mathematics functions
 */

#ifndef MCUXCLMATH_INTERNAL_H_
#define MCUXCLMATH_INTERNAL_H_

#include <mcuxClCore_Platform.h>

#include <internal/mcuxClMath_Internal_Functions.h>
#include <internal/mcuxClMath_Internal_Types.h>

/* The maximum number of pointers in the UPTRT for calls to mcuxClMath_InitLocalUptrt */
#define MATH_NO_OF_MAX_VIRTUALS 32U

#define MCUXCLMATH_SIZEOF_MATH_UPTRT MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(sizeof(uint16_t) * (MATH_NO_OF_MAX_VIRTUALS))

#endif /* MCUXCLMATH_INTERNAL_H_ */
