/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023, 2026 NXP                                            */
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
 * @file  mcuxClMath_Internal_NDash.h
 * @brief mcuxClMath: internal header of mcuxClMath_NDash
 */


#ifndef MCUXCLMATH_INTERNAL_NDASH_H_
#define MCUXCLMATH_INTERNAL_NDASH_H_

#include <mcuxClCore_Platform.h>


/**********************************************************/
/* Indices of operands in PKC workarea and UPTR table     */
/**********************************************************/
#define NDASH_T      0U
#define NDASH_N      1U
#define NDASH_NDASH  2U
#define NDASH_CONST2 3U
#define NDASH_CONST0 4U
#define NDASH_UPTRT_SIZE  5U
#define NDASH_UPTRT_OFFSET 18U /* NDash offset is after SECMODEXP_EXPT */

#endif /* MCUXCLMATH_INTERNAL_NDASH_H_ */
