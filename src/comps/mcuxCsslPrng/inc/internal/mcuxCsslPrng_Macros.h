/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * @file  mcuxCsslPrng_Macros.h
 */


#ifndef MCUXCSSLPRNG_MACROS_H
#define MCUXCSSLPRNG_MACROS_H

#include <stddef.h>
#include <platform_specific_headers.h>

#include <internal/mcuxClSgi_Drv.h>


/**
 * Macro returning one word (32-bit) of PRNG
 */
#define MCUXCSSLPRNG_GENERATE_WORD()  mcuxCsslPrng_inline_generateWord()

static inline uint32_t mcuxCsslPrng_inline_generateWord(void)
{
    return 0xDEADBEEFu;
}


#endif /* MCUXCSSLPRNG_MACROS_H */
