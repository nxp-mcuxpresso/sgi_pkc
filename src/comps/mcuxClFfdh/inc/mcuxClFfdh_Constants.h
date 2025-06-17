/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
 * @file  mcuxClFfdh_Constants.h
 * @brief Constant definitions of mcuxClFfdh component
 */


#ifndef MCUXCLFFDH_CONSTANTS_H
#define MCUXCLFFDH_CONSTANTS_H


#include <mcuxClCore_Platform.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @defgroup mcuxClFfdh_ParameterSizes mcuxClFfdh_ParameterSizes
 * @brief Defines domain parameter, key and signature sizes of @ref mcuxClFfdh
 * @ingroup mcuxClFfdh
 * @{
 */

/**
 * @addtogroup MCUXCLFFDH_FFDHE2048_SIZE
 * FFDH parameter size definitions for ffdhe2048
 * @{ */
#define MCUXCLFFDH_FFDHE2048_SIZE_PRIMEP                     (256U)
#define MCUXCLFFDH_FFDHE2048_SIZE_PRIMEQ                     (256U)
#define MCUXCLFFDH_FFDHE2048_SIZE_PUBLICKEY                  (MCUXCLFFDH_FFDHE2048_SIZE_PRIMEP)
#define MCUXCLFFDH_FFDHE2048_SIZE_PRIVATEKEY                 (MCUXCLFFDH_FFDHE2048_SIZE_PRIMEQ)
#define MCUXCLFFDH_FFDHE2048_SIZE_SHAREDSECRET               (MCUXCLFFDH_FFDHE2048_SIZE_PRIMEP)
/** @} */  /* MCUXCLFFDH_FFDHE2048_SIZE */

/**
 * @addtogroup MCUXCLFFDH_FFDHE3072_SIZE
 * FFDH parameter size definitions for ffdhe3072
 * @{ */
#define MCUXCLFFDH_FFDHE3072_SIZE_PRIMEP                     (384U)
#define MCUXCLFFDH_FFDHE3072_SIZE_PRIMEQ                     (384U)
#define MCUXCLFFDH_FFDHE3072_SIZE_PUBLICKEY                  (MCUXCLFFDH_FFDHE3072_SIZE_PRIMEP)
#define MCUXCLFFDH_FFDHE3072_SIZE_PRIVATEKEY                 (MCUXCLFFDH_FFDHE3072_SIZE_PRIMEQ)
#define MCUXCLFFDH_FFDHE3072_SIZE_SHAREDSECRET               (MCUXCLFFDH_FFDHE3072_SIZE_PRIMEP)
/** @} */  /* MCUXCLFFDH_FFDHE3072_SIZE */

/**
 * @addtogroup MCUXCLFFDH_FFDHE4096_SIZE
 * FFDH parameter size definitions for ffdhe4096
 * @{ */
#define MCUXCLFFDH_FFDHE4096_SIZE_PRIMEP                     (512U)
#define MCUXCLFFDH_FFDHE4096_SIZE_PRIMEQ                     (512U)
#define MCUXCLFFDH_FFDHE4096_SIZE_PUBLICKEY                  (MCUXCLFFDH_FFDHE4096_SIZE_PRIMEP)
#define MCUXCLFFDH_FFDHE4096_SIZE_PRIVATEKEY                 (MCUXCLFFDH_FFDHE4096_SIZE_PRIMEQ)
#define MCUXCLFFDH_FFDHE4096_SIZE_SHAREDSECRET               (MCUXCLFFDH_FFDHE4096_SIZE_PRIMEP)
/** @} */  /* MCUXCLFFDH_FFDHE4096_SIZE */

/**
 * @addtogroup MCUXCLFFDH_FFDHE6144_SIZE
 * FFDH parameter size definitions for ffdhe6144
 * @{ */
#define MCUXCLFFDH_FFDHE6144_SIZE_PRIMEP                     (768U)
#define MCUXCLFFDH_FFDHE6144_SIZE_PRIMEQ                     (768U)
#define MCUXCLFFDH_FFDHE6144_SIZE_PUBLICKEY                  (MCUXCLFFDH_FFDHE6144_SIZE_PRIMEP)
#define MCUXCLFFDH_FFDHE6144_SIZE_PRIVATEKEY                 (MCUXCLFFDH_FFDHE6144_SIZE_PRIMEQ)
#define MCUXCLFFDH_FFDHE6144_SIZE_SHAREDSECRET               (MCUXCLFFDH_FFDHE6144_SIZE_PRIMEP)
/** @} */  /* MCUXCLFFDH_FFDHE6144_SIZE */

/**
 * @addtogroup MCUXCLFFDH_FFDHE8192_SIZE
 * FFDH parameter size definitions for ffdhe8192
 * @{ */
#define MCUXCLFFDH_FFDHE8192_SIZE_PRIMEP                     (1024U)
#define MCUXCLFFDH_FFDHE8192_SIZE_PRIMEQ                     (1024U)
#define MCUXCLFFDH_FFDHE8192_SIZE_PUBLICKEY                  (MCUXCLFFDH_FFDHE8192_SIZE_PRIMEP)
#define MCUXCLFFDH_FFDHE8192_SIZE_PRIVATEKEY                 (MCUXCLFFDH_FFDHE8192_SIZE_PRIMEQ)
#define MCUXCLFFDH_FFDHE8192_SIZE_SHAREDSECRET               (MCUXCLFFDH_FFDHE8192_SIZE_PRIMEP)
/** @} */  /* MCUXCLFFDH_FFDHE8192_SIZE */

/**
 * @}
 */ /* mcuxClFfdh_ParameterSizes */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLFFDH_CONSTANTS_H */
