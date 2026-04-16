/*--------------------------------------------------------------------------*/
/* Copyright 2020-2026 NXP                                                  */
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
 * @file  mcuxCsslMemory_SecureCompare.h
 * @brief Include file for secure compare function
 */

#ifndef MCUXCSSLMEMORY_SECURECOMPARE_H
#define MCUXCSSLMEMORY_SECURECOMPARE_H

#include <mcuxCsslMemory_Types.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>

/**
 * @defgroup mcuxCsslMemory_SecureCompare mcuxCssl Memory Secure Compare
 * @brief Memory Compare Function protected against SPA and FA
 *
 * @ingroup mcuxCsslMemory
 * @{
 */

/**
 * @defgroup mcuxCsslMemory_SecureCompare_Functions mcuxCsslMemory_SecureCompare Function Definitions
 * @brief mcuxCsslMemory_SecureCompare Function Definitions
 *
 * @ingroup mcuxCsslMemory_SecureCompare
 * @{
 */

/**
 * @brief Securely compares the two memory regions @p lhs and @p rhs
 *
 * The implementation is secure in the following aspects:
 * 
 * * Constant execution time: The execution sequence of the code is always identical for equal @p length parameters,
 *     i.e. no branches are performed based on the data in @p pLhs or @p pRhs.
 * * Parameter integrity protection: An incorrect parameter checksum makes the function return immediately.
 * * Code flow protection: The function call is protected. Additionally, the result depends on all steps of the calculation.
 * * Random order memory access: an attacker shall not be able to distinguish the position of the difference between the two compared buffers.
 * * Blinded word compare: SPA protection.
 * * Integrity of the result is ensured. The accumulator of differences is checked twice when generating the return status (EQUAL or NOT_EQUAL).
 * 
 * @param chk    The parameter checksum, generated with #MCUX_CSSL_PI_PROTECT.
 * @param pLhs   The left-hand side data to compare. Must not be NULL.
 * @param pRhs   The right-hand side data to compare. Must not be NULL.
 * @param length The number of bytes to compare.
 * @return A status code encapsulated in a flow-protection type.
 * @retval #MCUXCSSLMEMORY_STATUS_ZERO_LENGTH If @p length is zero.
 * @retval #MCUXCSSLMEMORY_STATUS_EQUAL If the contents of @p lhs and @p rhs are equal and @p length is not zero.
 * @retval #MCUXCSSLMEMORY_STATUS_NOT_EQUAL If the contents of @p lhs and @p rhs are not equal.
 * @retval #MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER If either @p lhs or @p rhs was NULL, @p lhs and @p rhs are equal.
 * @retval #MCUXCSSLMEMORY_STATUS_FAULT If a fault was detected.
 * 
 * \implements{REQ_788364}
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_SecureCompare)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureCompare
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void const * pLhs,
    void const * pRhs,
    uint32_t length
);

/**
 * @}
 */

/**
 * @}
 */

#endif /* MCUXCSSLMEMORY_SECURECOMPARE_H */
