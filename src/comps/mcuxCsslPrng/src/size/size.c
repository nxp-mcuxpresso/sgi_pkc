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


#include <mcuxClCore_Platform.h>
#include <platform_specific_headers.h>
#include <mcuxCsslAnalysis.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()

#if defined(SCM)      /* S5xy */
#define MCUXCSSLPRNG_SCM_PRNG_ADDR  ((uint32_t) SCM_BASE + offsetof(SCM_Type, SCM_PRNG_OUT))
#elif defined(S3SCM)  /* S401 */
#define MCUXCSSLPRNG_SCM_PRNG_ADDR  ((uint32_t) S3SCM_BASE + offsetof(S3SCM_Type, S3SCM_PRNG_OUT))
#else
/* Avoid below error if stub is used. */
#endif

volatile uint8_t mcuxCsslPrng_prngSfrAddr_hi16[1u];
volatile uint8_t mcuxCsslPrng_prngSfrAddr_lo16[1u];

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
