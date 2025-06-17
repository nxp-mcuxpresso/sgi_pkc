/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @file  mcuxClEcc_Internal_Random.h
 * @brief internal header for abstracting random access in mcuxClEcc
 */


#ifndef MCUXCLECC_INTERNAL_RANDOM_H_
#define MCUXCLECC_INTERNAL_RANDOM_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClRandom.h>
#include <internal/mcuxClRandom_Internal_Functions.h>


/******************************************************************************/
/* Macro to generate high-quality random number in PKC workarea.              */
/******************************************************************************/
#define MCUXCLECC_FP_RANDOM_HQRNG_PKCWA(callerID, pSession, pOutPKCWA, length, pXorMask)                     \
    do{                                                                                                             \
        MCUXCLBUFFER_INIT(buffOutPKCWA, NULL, pOutPKCWA, length);                                                    \
        MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, pSession);                                                    \
        MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, buffOutPKCWA);                                                \
        MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, length);                                                      \
        MCUX_CSSL_DI_RECORD(sumOfRandomGenerateParams, pXorMask);                                                    \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandom_generate_internal(pSession, buffOutPKCWA, length, pXorMask));    \
    } while(false)

#define MCUXCLECC_FP_CALLED_RANDOM_HQRNG_PKCWA  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate_internal)


#endif /* MCUXCLECC_INTERNAL_RANDOM_H_ */
