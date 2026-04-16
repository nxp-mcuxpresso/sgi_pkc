/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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
 * @file  mcuxCsslPrng_Macros.h
 */


#ifndef MCUXCSSLPRNG_MACROS_H
#define MCUXCSSLPRNG_MACROS_H

#include <stddef.h>
#include <platform_specific_headers.h>

#include <mcuxClConfig.h> // Exported features flags header

#include <internal/mcuxClSgi_Drv.h>


/**
 * Macro returning one word (32-bit) of PRNG
 */
#define MCUXCSSLPRNG_GENERATE_WORD()  mcuxCsslPrng_inline_generateWord()

static inline uint32_t mcuxCsslPrng_inline_generateWord(void)
{
#if defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB)
    return 0xDEADBEEFU;
#elif defined(SCM)      /* S5xy */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_INTEGER_TO_POINTER("SCM SFR address")
    return SCM->SCM_PRNG_OUT;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_INTEGER_TO_POINTER()
#elif defined(S3SCM)  /* S401 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_INTEGER_TO_POINTER("SCM SFR address")
    return S3SCM->S3SCM_PRNG_OUT.reg;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_INTEGER_TO_POINTER()
#elif defined(MCUXCL_FEATURE_PRNG_SGI)
    return MCUX_CSSL_FP_RESULT(mcuxClSgi_Drv_getPrngWord());
#else
#error Unsupported platform
    return (uint32_t) 0xDEADBEEFu;
#endif
}


#endif /* MCUXCSSLPRNG_MACROS_H */
