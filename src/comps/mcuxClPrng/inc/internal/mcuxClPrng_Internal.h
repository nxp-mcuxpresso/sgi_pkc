/*--------------------------------------------------------------------------*/
/* Copyright 2022, 2024-2025 NXP                                            */
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
 * @file mcuxClPrng_Internal.h
 * @brief Top level header of mcuxClPrng component
 *
 * @defgroup mcuxClPrng mcuxClPrng
 * @brief component of Prng generation
 */

#ifndef MCUXCLPRNG_INTERNAL_H_
#define MCUXCLPRNG_INTERNAL_H_

#include <internal/mcuxClPrng_Internal_Types.h>
#include <internal/mcuxClPrng_Internal_Functions.h>



#include <mcuxClCore_Platform.h>
#include <platform_specific_headers.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClSgi_Drv.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * In case of SGi SFRSEED based PRNG, first we must backup SGI_CTRL and SGI_CTRL2.
 * Then  We need to set SMASKSW=0 and SMASKEN=0 to get random from SFRSEED and set SMASKSTEP = 1 to update SFRSEED on read.
 * On other types of PRNG this macro is empty
 */

#define MCUXCLPRNG_INIT() \
  mcuxClSgi_Drv_wait(); \
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCtrl)); \
  MCUX_CSSL_FP_FUNCTION_CALL(sgictrl__, mcuxClSgi_Drv_getCtrl()); \
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCtrl2)); \
  MCUX_CSSL_FP_FUNCTION_CALL(sgictrl2__, mcuxClSgi_Drv_getCtrl2()); \
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init)); \
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_SFR_CTRL2_SMASKSTEP));

/* In case of SGi SFRSEED based PRNG restore SGI_CTRL and SGI_CTRL2. In other types of PRNG do nothing. */
#define MCUXCLPRNG_RESTORE() \
  mcuxClSgi_Drv_wait(); \
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setCtrl)); \
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_setCtrl(sgictrl__)); \
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setCtrl2)); \
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_setCtrl2(sgictrl2__));

#define MCUXCLPRNG_GET_WORD(ret) \
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getSfrSeed)); \
  MCUX_CSSL_FP_FUNCTION_CALL(ret, mcuxClSgi_Drv_getSfrSeed())


/**
 * @brief Non-cryptographic PRNG data word generation function.
 *
 * This function returns a non-cryptographic random data word
 * The source of PRNG random number can be SCM or SGI:
 *  - In case of SCM it utilizes SCM_PRNG_OUT
 *  - In cas of SGI, the source is SFRMASK generator.
 *  - If none of above sources are available (PRNG_NONE), it returns fixed number 0xF0F0F0F0u
 *
 * The seeding PRNG sources is not supported.
 *
 * @return 32-bit random data
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPrng_generate_word)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClPrng_generate_word(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLPRNG_INTERNAL_H_ */
