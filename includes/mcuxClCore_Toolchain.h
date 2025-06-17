/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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

#ifndef MCUXCLCORE_TOOLCHAIN_H_
#define MCUXCLCORE_TOOLCHAIN_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxCl_Core_Swap64)
static inline uint64_t mcuxCl_Core_Swap64(uint64_t value)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(value);
#else
    return ((value >> 56) & 0x00000000000000FFULL) |
           ((value >> 40) & 0x000000000000FF00ULL) |
           ((value >> 24) & 0x0000000000FF0000ULL) |
           ((value >>  8) & 0x00000000FF000000ULL) |
           ((value <<  8) & 0x000000FF00000000ULL) |
           ((value << 24) & 0x0000FF0000000000ULL) |
           ((value << 40) & 0x00FF000000000000ULL) |
           ((value << 56) & 0xFF00000000000000ULL);
#endif
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxCl_Core_Swap32)
static inline uint32_t mcuxCl_Core_Swap32(uint32_t value)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(value);
#else
    return ((value >> 24) & 0x000000FFUL) |
           ((value << 24) & 0xFF000000UL) |
           ((value >>  8) & 0x0000FF00UL) |
           ((value <<  8) & 0x00FF0000UL);
#endif
}


#endif /* MCUXCLCORE_TOOLCHAIN_H_ */
