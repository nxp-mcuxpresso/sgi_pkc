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

/**
 * @file  mcuxClSgi_Types.h
 * @brief Type and associated constant definitions of the mcuxClSgi component.
 */

#ifndef MCUXCLSGI_TYPES_H_
#define MCUXCLSGI_TYPES_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClSgi_Types mcuxClSgi_Types
 * @brief Defines the types and associated constants of the @ref mcuxClSgi component.
 * @ingroup mcuxClSgi
 * @{
 */

/**
 * @brief SGI status code
 *
 * This type provides information about the status of the SGI operation that
 * has been performed.
 */
typedef uint32_t mcuxClSgi_Status_t;

/**
 * @}
 */ /* mcuxClSgi_Types */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLSGI_TYPES_H_ */
