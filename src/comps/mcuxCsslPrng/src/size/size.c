/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2026 NXP                                                 */
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

#include <mcuxClCore_Platform.h>
#include <platform_specific_headers.h>
#include <mcuxCsslAnalysis.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()

#if defined(SCM)      /* S5xy */
  #define MCUXCSSLPRNG_SCM_PRNG_ADDR  ((uint32_t) SCM_BASE + offsetof(SCM_Type, SCM_PRNG_OUT))
#elif defined(S3SCM)  /* S401 */
  #define MCUXCSSLPRNG_SCM_PRNG_ADDR  ((uint32_t) S3SCM_BASE + offsetof(S3SCM_Type, S3SCM_PRNG_OUT))
#elif defined(MCUXCL_FEATURE_PRNG_SGI)
  #include <internal/mcuxClSgi_SfrAccess.h>
  #define MCUXCSSLPRNG_SGI_PRNG_ADDR ((uint32_t) SGI_SFR_BASE + offsetof(SGI_Type, SGI_PRNG_SW_READ))
#elif defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB)
/* Avoid below error if stub is used. */
#else
  #error Unsupported platform
#endif

#if defined(MCUXCL_FEATURE_PRNG_SGI)
#if !defined(__m56800E__)
MCUX_CSSL_ANALYSIS_CLANG_START_SUPPRESS_WARNING(-Wgnu-folding-constant, " Usage of the offsetof within specification of array size triggers warning in armclang. Disable it temporarily");
#endif
/* we bias the array size by + 1 so it's never 0 when (MCUXCSSLPRNG_SGI_PRNG_ADDR >> 16) == 0 */
/* enum forces compile-time evaluation of the array sizes,
 * which solves an issue with certain compilers when using offsetof in array dimension declarations */
enum { MCUXCSSLPRNG_SGI_PRNG_ADDR_HI16 = ((MCUXCSSLPRNG_SGI_PRNG_ADDR >> 16u) + 1u) };
enum { MCUXCSSLPRNG_SGI_PRNG_ADDR_LO16 = (MCUXCSSLPRNG_SGI_PRNG_ADDR & 0xFFFFu) };
volatile uint8_t mcuxCsslPrng_prngSfrAddr_hi16[MCUXCSSLPRNG_SGI_PRNG_ADDR_HI16];
volatile uint8_t mcuxCsslPrng_prngSfrAddr_lo16[MCUXCSSLPRNG_SGI_PRNG_ADDR_LO16];
#if !defined(__m56800E__)
MCUX_CSSL_ANALYSIS_CLANG_STOP_SUPPRESS_WARNING(-Wgnu-folding-constant);
#endif
#elif defined(MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB) && MCUXCL_FEATURE_CSSL_MEMORY_PRNG_STUB == 1
volatile uint8_t mcuxCsslPrng_prngSfrAddr_hi16[1u];
volatile uint8_t mcuxCsslPrng_prngSfrAddr_lo16[1u];
#else
/* we bias the array size by + 1 so it's never 0 when (MCUXCSSLPRNG_SCM_PRNG_ADDR >> 16) == 0 */
/* enum forces compile-time evaluation of the array sizes,
 * which solves an issue with certain compilers when using offsetof in array dimension declarations */
enum { MCUXCSSLPRNG_SCM_PRNG_ADDR_HI16 = ((MCUXCSSLPRNG_SCM_PRNG_ADDR >> 16u) + 1u) };
enum { MCUXCSSLPRNG_SCM_PRNG_ADDR_LO16 = (MCUXCSSLPRNG_SCM_PRNG_ADDR & 0xFFFFu) };
volatile uint8_t mcuxCsslPrng_prngSfrAddr_hi16[MCUXCSSLPRNG_SCM_PRNG_ADDR_HI16];
volatile uint8_t mcuxCsslPrng_prngSfrAddr_lo16[MCUXCSSLPRNG_SCM_PRNG_ADDR_LO16];
#endif

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
