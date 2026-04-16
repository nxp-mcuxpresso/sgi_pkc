/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023-2026 NXP                                            */
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
 * @file  mcuxClRsa_Internal_Macros.h
 * @brief Internal macros of the mcuxClRsa component
 */

#ifndef MCUXCLRSA_INTERNAL_MACROS_H_
#define MCUXCLRSA_INTERNAL_MACROS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <stdint.h>
#include <mcuxClCore_Macros.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup MCUXCLRSA_INTERNAL_DEFINES_ MCUXCLRSA_INTERNAL_DEFINES_
 * @brief Internal macros of the mcuxClRsa component.
 * @ingroup mcuxClRsa_Internal_Defines
 * @{
 */
#define MCUXCLRSA_PSS_PADDING1_LEN (8U)
    ///< Define for the PSS padding1 length.

#define MCUXCLRSA_HASH_MIN_SIZE MCUXCLHASH_STATE_SIZE_MIN
    ///< Defines the minimum size of the hash algorithms

#define MCUXCLRSA_HASH_MAX_SIZE MCUXCLHASH_OUTPUT_SIZE_SHA_512
    ///< Defines the maximum size of the hash algorithms

#define MCUXCLRSA_MIN_MODLEN (128U)
    ///< Defines the minimum size of the rsa modulus byte length

#ifdef MCUXCL_FEATURE_RSA_8K_KEYS
#define MCUXCLRSA_MAX_MODLEN (1024U)
    ///< Defines the maximum size of the rsa modulus byte length
#else
#define MCUXCLRSA_MAX_MODLEN (512U)
    ///< Defines the maximum size of the rsa modulus byte length
#endif

#if defined(MCUXCL_FEATURE_PKC_RAM_4KB)
#define MCUXCLRSA_MAX_MODLEN_EXPTEMP_IN_PKCRAM    (MCUXCLKEY_SIZE_3072/8U)
    ///< Defines the maximum size of the rsa modulus byte length so that expTemp buffer can be located in PKC RAM
#elif defined(MCUXCL_FEATURE_PKC_RAM_8KB)
#define MCUXCLRSA_MAX_MODLEN_EXPTEMP_IN_PKCRAM    (MCUXCLKEY_SIZE_6144/8U)
    ///< Defines the maximum size of the rsa modulus byte length so that expTemp buffer can be located in PKC RAM
#else
#error PKC_RAM size feature not properly defined
#endif /* MCUXCL_FEATURE_PKC_RAM_8KB */
/** @} */


/**
 * @defgroup MCUXCLRSA_INTERNAL_MACROS_ MCUXCLRSA_INTERNAL_MACROS_
 * @brief Internal macros of the mcuxClRsa component.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#ifdef MCUXCL_FEATURE_RSA_8K_KEYS
#define MCUXCLRSA_GET_MINIMUM_SECURITY_STRENGTH(keyBitLength) \
        (((keyBitLength) <= 1024U) ? 80U :  \
        (((keyBitLength) <= 2048U) ? 112U : \
        (((keyBitLength) <= 3072U) ? 128U : \
        (((keyBitLength) <= 4096U) ? 152U : \
        (((keyBitLength) <= 6144U) ? 176U : \
                                     200U))))) ///< Macro to determine the minimal security strength that
                                               ///< needs to be provided by the RNG for RSA keys with
                                               ///< lengths from 1024 bits to 8192 bits.
                                               ///< Numbers taken from NIST SP 800-56B REV. 2, Table 2 and Appendix D
#else
#define MCUXCLRSA_GET_MINIMUM_SECURITY_STRENGTH(keyBitLength) \
        (((keyBitLength) <= 1024U) ? 80U :  \
        (((keyBitLength) <= 2048U) ? 112U : \
        (((keyBitLength) <= 3072U) ? 128U : \
                                     152U))) ///< Macro to determine the minimal security strength that
                                             ///< needs to be provided by the RNG for RSA keys with
                                             ///< lengths from 1024 bits to 4096 bits.
                                             ///< Numbers taken from NIST SP 800-56B REV. 2, Table 2 and Appendix D
#endif /* #ifdef MCUXCL_FEATURE_RSA_8K_KEYS */

#define MCUXCLRSA_MAX_LOOP_ITER_P  (5U)   /* Value used to compute maximum number of iterations for generating p according to FIPS186-5 */
#define MCUXCLRSA_MAX_LOOP_ITER_Q  (10U)   /* Value used to compute maximum number of iterations for generating q according to FIPS186-5 */

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLRSA_INTERNAL_MACROS_H_ */

