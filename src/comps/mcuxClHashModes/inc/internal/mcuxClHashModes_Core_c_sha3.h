/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2025 NXP                                                 */
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

/** @file  mcuxClHashModes_core_c_sha3.h
 *  @brief Internal definitions and declarations of the *CORE* layer dedicated
 *         to the software implementation of SHA-3
 */

#ifndef MCUXCLHASHMODES_CORE_SW_SHA3_H_
#define MCUXCLHASHMODES_CORE_SW_SHA3_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClHash_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************
 * Function declarations
 **********************************************************/

/**
 * @brief Keccak Core hash processing
 *
 * This function takes sha3 state and performs Keccak permutatios.
 *
 * @param[in,out] pState    Pointer to the 200 byte (5*5*64 = 1600 bits) state
 *
 * @return void
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClHashModes_core_c_keccak)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHashModes_core_c_keccak(uint32_t *pState);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLHASHMODES_CORE_SW_SHA3_H_ */
