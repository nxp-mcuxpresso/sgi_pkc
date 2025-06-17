/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @file  mcuxClKey_Constants.h
 * @brief Constants for the mcuxClKey component.
 */

#ifndef MCUXCLKEY_CONSTANTS_H_
#define MCUXCLKEY_CONSTANTS_H_

#include <mcuxCsslAnalysis.h>
#include <mcuxClConfig.h> // Exported features flags header

/**********************************************
 * CONSTANTS
 **********************************************/
/**
 * @defgroup mcuxClKey_Macros mcuxClKey_Macros
 * @brief Defines all macros of @ref mcuxClKey
 * @ingroup mcuxClKey
 * @{
 */
/**
 * @defgroup MCUXCLKEY_STATUS_  MCUXCLKEY_STATUS_
 * @brief Return code definitions
 * @{
 */
#define MCUXCLKEY_STATUS_OK                          ((mcuxClKey_Status_t) 0x07772E03u)  ///< Key operation successful
#define MCUXCLKEY_STATUS_ERROR                       ((mcuxClKey_Status_t) 0x07775330u)  ///< Error occured during Key operation
#define MCUXCLKEY_STATUS_FAILURE                     ((mcuxClKey_Status_t) 0x07775334u)  ///< Failure during execution
#define MCUXCLKEY_STATUS_INVALID_INPUT               ((mcuxClKey_Status_t) 0x07775338u)  ///< Invalid input
#define MCUXCLKEY_STATUS_ERROR_MEMORY_ALLOCATION     ((mcuxClKey_Status_t) 0x0777533Cu)  ///< Memory allocation error during Key operation
#define MCUXCLKEY_STATUS_RNG_ERROR                   ((mcuxClKey_Status_t) 0x07775374u)  ///< Random number (DRBG / PRNG) error (unexpected behavior)
#define MCUXCLKEY_STATUS_FAULT_ATTACK                ((mcuxClKey_Status_t) 0x0777F0F0u)  ///< Fault attack detected
#define MCUXCLKEY_STATUS_CRC_NOT_OK                  ((mcuxClKey_Status_t) 0x077753FCu)  ///< CRC verification failed
#define MCUXCLKEY_STATUS_NOT_SUPPORTED               ((mcuxClKey_Status_t) 0x07775370u)  ///< Functionality not supported
#define MCUXCLKEY_STATUS_ITERATIONS_EXCEEDED         ((mcuxClKey_Status_t) 0x07775378u)  ///< Maximum interations exceeded, during prime generation for RSA
#define MCUXCLKEY_STATUS_VALIDATION_PASSED           ((mcuxClKey_Status_t) 0x07772E07u)  ///< Key validation successful
#define MCUXCLKEY_STATUS_VALIDATION_FAILED           ((mcuxClKey_Status_t) 0x07778930u)  ///< Key validation failed
/** @} */

/**
 * @defgroup MCUXCLKEY_LOADSTATUS_ MCUXCLKEY_LOADSTATUS_
 * @brief Load location options
 * @ingroup mcuxClKey_Macros
 * @{ */
#define MCUXCLKEY_LOADSTATUS_NOTLOADED           (0x0000U)   ///< Key not loaded

#define MCUXCLKEY_LOADSTATUS_LOCATION_MASK       (0x000FU)   ///< Bit mask for the key location
#define MCUXCLKEY_LOADSTATUS_LOCATION_NONE       (0x0000U)   ///< Key is not loaded to any location
#define MCUXCLKEY_LOADSTATUS_LOCATION_COPRO      (0x0001U)   ///< Key is loaded to a HW IP slot

#define MCUXCLKEY_LOADSTATUS_OPTIONS_MASK        (0xFFF0U)   ///< Bit mask for additional option bits of a key load status
#define MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED  (0x0010U)   ///< Do not flush the key after the operation (for Symmetric keys only)
#define MCUXCLKEY_LOADSTATUS_OPTIONS_WRITEONLY   (0x0020U)   ///< Key is loaded to a location that is write-only (e.g., SGI WO key slots)
/** @} */


/* Define algorithm IDs */
/**
 * @defgroup mcuxClKey_KeyTypes mcuxClKey_KeyTypes
 * @brief Defines all key types of @ref mcuxClKey
 * @ingroup mcuxClKey_Macros
 * @{
 */
#define MCUXCLKEY_ALGO_ID_DES                                (0x0030D000u)  ///< DES key
#define MCUXCLKEY_ALGO_ID_AES                                (0x00F01000u)  ///< AES key
#define MCUXCLKEY_ALGO_ID_RSA                                (0x00E02000u)  ///< RSA key
#define MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP                       (0x00D03000u)  ///< ECC key using Short Weierstrass Curve over GF(p)
#define MCUXCLKEY_ALGO_ID_ECC_SHWS_GF2M                      (0x00C04000u)  ///< ECC key using Short Weierstrass Curve over GF(2^m)
#define MCUXCLKEY_ALGO_ID_ECC_MONTDH                         (0x00B05000u)  ///< ECC key for MontDH key exchange scheme
#define MCUXCLKEY_ALGO_ID_ECC_EDDSA                          (0x00A06000u)  ///< ECC key for EdDSA signature scheme
#define MCUXCLKEY_ALGO_ID_HMAC                               (0x00907000u)  ///< HMAC key
#define MCUXCLKEY_ALGO_ID_SM4                                (0x00808000u)  ///< SM4 key
#define MCUXCLKEY_ALGO_ID_SM2                                (0x00809000u)  ///< SM2 key
#define MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP_EPHEMERAL_CUSTOM      (0x00709000u)  ///< ECC key using Short Weierstrass Curve over GF(p) with ephemeral custom domain parameters
#define MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM         (0x0060A000u)  ///< ECC key using Short Weierstrass Curve over GF(p) with static custom domain parameters
#define MCUXCLKEY_ALGO_ID_KYBER                              (0x0050B000u)  ///< Kyber key
#define MCUXCLKEY_ALGO_ID_MLDSA                              (0x0040C000u)  ///< MLDSA key
#define MCUXCLKEY_ALGO_ID_LMS                                (0x0010E000u)  ///< LMS key TODO CLNS-14347: check
#define MCUXCLKEY_ALGO_ID_GMAC                               (0x00601000u)  ///< GMAC H key
#define MCUXCLKEY_ALGO_ID_FFDH                               (0x0020E000u)  ///< FFDH key
#define MCUXCLKEY_ALGO_ID_ALGO_MASK                          (0x00FFF000u)  ///< Mask for Algorithm

#define MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY        (0x00000000u)  ///< Symmetric key
#define MCUXCLKEY_ALGO_ID_PUBLIC_KEY           (0x88000000u)  ///< Public key
#define MCUXCLKEY_ALGO_ID_PRIVATE_KEY          (0x44000000u)  ///< Private key
#define MCUXCLKEY_ALGO_ID_PRIVATE_KEY_CRT      (0x66000000u)  ///< Private RSA key in CRT format
#define MCUXCLKEY_ALGO_ID_KEY_PAIR             (0xCC000000u)  ///< Key pair
#define MCUXCLKEY_ALGO_ID_PRIVATE_KEY_CRT_DFA  (0xEE000000u)  ///< RSA key pair, with the private part in CRT format

#define MCUXCLKEY_ALGO_ID_USAGE_MASK           (0xFF000000u)  ///< Mask for Key Usage
/** @} */

/* Define key sizes */
/**
 * @defgroup mcuxClKey_KeySize mcuxClKey_KeySize
 * @brief Defines all key sizes of @ref mcuxClKey
 * @ingroup mcuxClKey
 * @{
 */
#define MCUXCLKEY_SIZE_NOTUSED           0u      ///< key length field is not used (e.g. ECC keys)
#define MCUXCLKEY_SIZE_64                8u      ///<  64 bit key, size in bytes
#define MCUXCLKEY_SIZE_128               16u     ///< 128 bit key, size in bytes
#define MCUXCLKEY_SIZE_160               20u     ///< 160 bit key, size in bytes
#define MCUXCLKEY_SIZE_192               24u     ///< 192 bit key, size in bytes
#define MCUXCLKEY_SIZE_224               28u     ///< 224 bit key, size in bytes
#define MCUXCLKEY_SIZE_256               32u     ///< 256 bit key, size in bytes
#define MCUXCLKEY_SIZE_320               40u     ///< 320 bit key, size in bytes
#define MCUXCLKEY_SIZE_384               48u     ///< 348 bit key, size in bytes
#define MCUXCLKEY_SIZE_512               64u     ///< 512 bit key, size in bytes
#define MCUXCLKEY_SIZE_521               66u     ///< 521 bit key, size in bytes
#define MCUXCLKEY_SIZE_1024              1024u   ///< 1024 bit key, size in bits
#define MCUXCLKEY_SIZE_2048              2048u   ///< 2048 bit key, size in bits
#define MCUXCLKEY_SIZE_3072              3072u   ///< 3072 bit key, size in bits
#define MCUXCLKEY_SIZE_4096              4096u   ///< 4096 bit key, size in bits
#define MCUXCLKEY_SIZE_6144              6144u   ///< 6144 bit key, size in bits
#define MCUXCLKEY_SIZE_8192              8192u   ///< 8192 bit key, size in bits

// TODO CLNS-6135: replace these divides by a macro that ensures rounding up
#define MCUXCLKEY_SIZE_64_IN_WORDS       (MCUXCLKEY_SIZE_64 / sizeof(uint32_t))      ///< 64 bit key, size in words
#define MCUXCLKEY_SIZE_128_IN_WORDS      (MCUXCLKEY_SIZE_128 / sizeof(uint32_t))     ///< 128 bit key, size in words
#define MCUXCLKEY_SIZE_160_IN_WORDS      (MCUXCLKEY_SIZE_160 / sizeof(uint32_t))     ///< 160 bit key, size in words
#define MCUXCLKEY_SIZE_192_IN_WORDS      (MCUXCLKEY_SIZE_192 / sizeof(uint32_t))     ///< 192 bit key, size in words
#define MCUXCLKEY_SIZE_224_IN_WORDS      (MCUXCLKEY_SIZE_224 / sizeof(uint32_t))     ///< 224 bit key, size in words
#define MCUXCLKEY_SIZE_256_IN_WORDS      (MCUXCLKEY_SIZE_256 / sizeof(uint32_t))     ///< 256 bit key, size in words
#define MCUXCLKEY_SIZE_320_IN_WORDS      (MCUXCLKEY_SIZE_320 / sizeof(uint32_t))     ///< 320 bit key, size in words
#define MCUXCLKEY_SIZE_384_IN_WORDS      (MCUXCLKEY_SIZE_384 / sizeof(uint32_t))     ///< 348 bit key, size in words
#define MCUXCLKEY_SIZE_512_IN_WORDS      (MCUXCLKEY_SIZE_512 / sizeof(uint32_t))     ///< 512 bit key, size in words
#define MCUXCLKEY_SIZE_521_IN_WORDS      ((MCUXCLKEY_SIZE_521 + sizeof(uint32_t) - 1u) / sizeof(uint32_t))     ///< 521 bit key, size in words
#define MCUXCLKEY_SIZE_1024_IN_WORDS     (MCUXCLKEY_SIZE_1024 / (sizeof(uint32_t) * 8u))    ///< 1024 bit key, size in words
#define MCUXCLKEY_SIZE_2048_IN_WORDS     (MCUXCLKEY_SIZE_2048 / (sizeof(uint32_t) * 8u))    ///< 2048 bit key, size in words
#define MCUXCLKEY_SIZE_3072_IN_WORDS     (MCUXCLKEY_SIZE_3072 / (sizeof(uint32_t) * 8u))    ///< 3072 bit key, size in words
#define MCUXCLKEY_SIZE_4096_IN_WORDS     (MCUXCLKEY_SIZE_4096 / (sizeof(uint32_t) * 8u))    ///< 4096 bit key, size in words
#define MCUXCLKEY_SIZE_6144_IN_WORDS     (MCUXCLKEY_SIZE_6144 / (sizeof(uint32_t) * 8u))    ///< 6144 bit key, size in words
#define MCUXCLKEY_SIZE_8192_IN_WORDS     (MCUXCLKEY_SIZE_8192 / (sizeof(uint32_t) * 8u))    ///< 8192 bit key, size in words
/** @} */

#define MCUXCLKEY_WA_SIZE_MAX 0U


/**
 * @defgroup mcuxClKey_KeyLoadOption mcuxClKey_KeyLoadOption
 * @brief Defines all key load options (slots, others) of @ref mcuxClKey
 * @ingroup mcuxClKey
 * @{
 */

#define MCUXCLKEY_LOADOPTION_MASK                    (0xffffffffU)

/** Defines for supported key slots */
#define MCUXCLKEY_LOADOPTION_SLOT_MASK               (0xffU)
#define MCUXCLKEY_LOADOPTION_SLOT_INVALID            (MCUXCLKEY_LOADOPTION_SLOT_MASK)


#define MCUXCLKEY_LOADOPTION_SLOT_COPRO_MASK         (0xc0U)
#define MCUXCLKEY_LOADOPTION_SLOT_COPRO_SHIFT        (6U)
#define MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI          ((uint32_t)0x01U << MCUXCLKEY_LOADOPTION_SLOT_COPRO_SHIFT)

#define MCUXCLKEY_LOADOPTION_SLOT_SLOT_MASK          (0x3fU)
#define MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT         (0U)
#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_0          (MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI | ((uint32_t)0U << MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT)) ///< SGI key slot 0. Reserved for CL internal key usage.
#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_1          (MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI | ((uint32_t)1U << MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT)) ///< SGI key slot 1. Reserved for CL internal key usage.
#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_2          (MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI | ((uint32_t)2U << MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT)) ///< SGI key slot 2
#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_3          (MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI | ((uint32_t)3U << MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT)) ///< SGI key slot 3
#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_4          (MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI | ((uint32_t)4U << MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT)) ///< SGI key slot 4
#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_5          (MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI | ((uint32_t)5U << MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT)) ///< SGI key slot 5
#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_6          (MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI | ((uint32_t)6U << MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT)) ///< SGI key slot 6
#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_7          (MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI | ((uint32_t)7U << MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT)) ///< SGI key slot 7

#define MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP      MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_4 ///< Key slot containing an unwrapped key. // TODO CLNS-16195: not the same on all platforms


/** Defines for other key options that can be encoded in a slot */
#define MCUXCLKEY_LOADOPTION_ALREADYLOADED_MASK      (0x100U)
#define MCUXCLKEY_LOADOPTION_ALREADYLOADED_SHIFT     (8U)
#define MCUXCLKEY_LOADOPTION_ALREADYLOADED           ((uint32_t)0x1U << MCUXCLKEY_LOADOPTION_ALREADYLOADED_SHIFT) ///< Option: the key is already loaded; only set the fields in the key object

/** Defines for RFU bits */
#define MCUXCLKEY_LOADOPTION_RFU_MASK                (0xfffffe00U)
// planned RFU: option for runtime WO keys


/** @} */

/** @} */

#endif /* MCUXCLKEY_CONSTANTS_H_ */
