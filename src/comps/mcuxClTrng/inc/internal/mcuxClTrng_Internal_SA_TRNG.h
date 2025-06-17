/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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

/** @file  mcuxClTrng_Internal_SA_TRNG.h
 *  @brief Provide macros for mcuxClTrng internal use.
 * This header declares internal macros to deduplicate code and support for internal use only. 
 */

#ifndef MCUXCLTRNG_INTERNAL_SA_TRNG_H_
#define MCUXCLTRNG_INTERNAL_SA_TRNG_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <platform_specific_headers.h>
#include <internal/mcuxClTrng_SfrAccess.h>
#include <internal/mcuxClTrng_Internal_Constants.h>

#define MCUXCLTRNG_ERROR_LIMIT                          (3u)
#define MCUXCLTRNG_SA_TRNG_HW_DUAL_OSCILLATOR_MODE      (1u)

#define MCUXCLTRNG_SA_TRNG_NUMBEROFENTREGISTERS         (8u)

#endif /* MCUXCLTRNG_INTERNAL_SA_TRNG_H_ */
