/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @file  mcuxClKdfModes_Algorithms.h
 * @brief Supported algorithms for key derivation
 */

#ifndef MCUXCLKDFMODES_ALGORITHMS_H_
#define MCUXCLKDFMODES_ALGORITHMS_H_

#include <mcuxClConfig.h> // Exported features flags header

/**
 * @defgroup mcuxClKdfModes_Algorithms mcuxClKdfModes_Algorithms
 * @brief Defines all algorithms of @ref mcuxClKdfModes
 * @ingroup mcuxClKdfModes
 * @{
 */

#include <mcuxClKdfModes_Algorithms_NIST_SP800_108.h>
#include <mcuxClKdfModes_Algorithms_NIST_SP800_56C.h>
#include <mcuxClKdfModes_Algorithms_HKDF.h>
#include <mcuxClKdfModes_Algorithms_PBKDF2.h>

/** @} */

#endif /* MCUXCLKDFMODES_ALGORITHMS_H_ */
