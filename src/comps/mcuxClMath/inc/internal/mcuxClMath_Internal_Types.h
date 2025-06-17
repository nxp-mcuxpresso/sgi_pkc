/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021, 2023-2024 NXP                                       */
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
 * @file  mcuxClMath_Internal_Types.h
 * @brief Type definitions for the mcuxClMath component
 */


#ifndef MCUXCLMATH_INTERNAL_TYPES_H_
#define MCUXCLMATH_INTERNAL_TYPES_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>


/**********************************************
 * CONSTANTS
 **********************************************/
/* None */

/**********************************************
 * TYPEDEFS
 **********************************************/
/**
 * @defgroup mcuxClMath_Internal_Types mcuxClMath_Internal_Types
 * @brief Defines all macros of @ref mcuxClMath
 * @ingroup mcuxClMath
 * @{
 */

/**
 * @brief Type for error codes used by Math component functions.
 */
typedef uint32_t mcuxClMath_Status_t;

/**
 * @brief Deprecated type for error codes used by code-flow protected Math component functions.
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMath_Status_t) mcuxClMath_Status_Protected_t;

#define MCUXCLMATH_STATUS_OK        ((mcuxClMath_Status_t) 0x0FF32E03u)  ///< Math operation successful
#define MCUXCLMATH_ERRORCODE_OK     MCUXCLMATH_STATUS_OK                 ///< \deprecated Replaced by MCUXCLMATH_STATUS_OK
#define MCUXCLMATH_STATUS_ERROR     ((mcuxClMath_Status_t) 0x0FF35330u)  ///< Error occurred during Math operation
#define MCUXCLMATH_ERRORCODE_ERROR  MCUXCLMATH_STATUS_ERROR              ///< \deprecated Replaced by MCUXCLMATH_STATUS_ERROR

/**
 * @brief Flag to indicate if X and N are coprime for mcuxClMath_ModInv.
 */
#define MCUXCLMATH_XN_COPRIME       0x5A5A5A5Au
#define MCUXCLMATH_XN_NOT_COPRIME   0x0u


/**
 * @}
 */ /* mcuxClMath_Internal_Types */


#endif /* MCUXCLMATH_INTERNAL_TYPES_H_ */
