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
 * @file  mcuxCsslMemory_Internal_Set.h
 * @brief header file of internal memory set function
 */


#ifndef MCUXCSSLMEMORY_INTERNAL_SET_H_
#define MCUXCSSLMEMORY_INTERNAL_SET_H_


#include <stdint.h>
#include <stddef.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>

/**
 * @defgroup mcuxCsslMemory_Int_Set_Functions mcuxCsslMemory_Int_Set Function Definitions
 * @brief mcuxCsslMemory_Int_Set Function Definitions
 *
 * @ingroup mcuxCsslMemory_Int_Set
 * @{
 */


/**
 * @brief Set @p length bytes of data at @p pDst.
 *
 * The implementation is robust against fault attacks.
 *
 * @post
 *  - Data Integrity: Expunge(pDst + length)
 *
 * @param[in]  pDst         The destination pointer to buffer to be set. Must not be NULL.
 * @param[in]  val          The byte value to be set.
 * @param[in]  length       The size in bytes to set.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_Int_Set)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_Set
(
    uint8_t * pDst,
    uint8_t val,
    uint32_t length
);


#endif /* MCUXCSSLMEMORY_INTERNAL_SET_H_ */
