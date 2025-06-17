/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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

/**
 * @file  mcuxClMath_Internal_ModSquareRoot.h
 * @brief mcuxClMath: internal header of modular square root
 */


#ifndef MCUXCLMATH_INTERNAL_MODSQUAREROOT_H_
#define MCUXCLMATH_INTERNAL_MODSQUAREROOT_H_

#include <mcuxClCore_Platform.h>


/**********************************************************/
/* Indices of operands in PKC workarea and UPTR table     */
/**********************************************************/
#define MODSQRT_Q      0u
#define MODSQRT_P      1u
#define MODSQRT_A      2u
#define MODSQRT_Y      3u
#define MODSQRT_S      4u
#define MODSQRT_M      5u
#define MODSQRT_B      6u
#define MODSQRT_T      7u
#define MODSQRT_SIZE   8u

#endif /* MCUXCLMATH_INTERNAL_MODSQUAREROOT_H_ */
