/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * @file  mcuxCsslMemory_Internal_Compare.h
 * @brief Internal header of mcuxCsslMemory_Int_Comp
 */


#ifndef MCUXCSSLMEMORY_INTERNAL_COMPARE_H_
#define MCUXCSSLMEMORY_INTERNAL_COMPARE_H_

#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compares the two memory regions @p lhs and @p rhs - internal use only
 * 
 * The implementation is secure in the following aspects:
 * - Constant execution time: The execution sequence of the code is always identical for equal @p length parameters,
 *     i.e. no branches are performed based on the data in @p pLhs or @p pRhs.
 * - Code flow protection: The function call is protected. Additionally, the result depends on all steps of the calculation.
 * - Integrity of the result is ensured. The accumulator of differences is checked twice when generating the return status (EQUAL or NOT_EQUAL).
 *
 * @param[in] pLhs   The left-hand side data to compare.
 * @param[in] pRhs   The right-hand side data to compare.
 * @param     length The number of bytes to compare.
 * 
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pLhs + pRhs + length)
 *
 * @return A status code encapsulated in a flow-protection type.
 * @retval #MCUXCSSLMEMORY_STATUS_EQUAL If the contents of @p lhs and @p rhs are equal.
 * @retval #MCUXCSSLMEMORY_STATUS_NOT_EQUAL If the contents of @p lhs and @p rhs are not equal.
 * @retval #MCUXCSSLMEMORY_STATUS_FAULT If a fault was detected.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_Int_Comp)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_Int_Comp(
    const uint8_t * pLhs,
    const uint8_t * pRhs,
    uint32_t length
);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  /* MCUXCSSLMEMORY_INTERNAL_COMPARE_H */
