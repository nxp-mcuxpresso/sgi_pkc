/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * @file  mcuxCsslMemory_SecureXOR.h
 * @brief Include file for secure XOR function
 */

#ifndef MCUXCSSLMEMORY_SECUREXOR_H
#define MCUXCSSLMEMORY_SECUREXOR_H

#include <mcuxCsslMemory_Types.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @defgroup mcuxCsslMemory_SecureXOR mcuxCssl Memory Secure XOR
 * @brief Control Flow Protected Secure Memory XOR Function
 *
 * @ingroup mcuxCsslMemory
 * @{
 */

/**
 * @defgroup mcuxCsslMemory_SecureXOR_Functions mcuxCsslMemory_SecureXOR Function Definitions
 * @brief mcuxCsslMemory_SecureXOR Function Definitions
 *
 * @ingroup mcuxCsslMemory_SecureXOR
 * @{
 */

/**
 * @brief XORs @p length bytes of data from @p pSrc and @p pSrc2 and stores it in @p pDst
 *
 * The implementation is secure in the following aspects:
 * * Random order memory access
 * * Parameter integrity protection: An incorrect parameter checksum makes the function return immediately.
 * * Code flow protection: The function call is protected. Additionally, the result depends on all steps of the calculation.
 * * Buffer overflow protection: No data is written to @p pDst beyond @p dstLength bytes.
 *
 * @param[in]   chk        The parameter checksum, generated with #MCUX_CSSL_PI_PROTECT.
 * @param[in]   pSrc       The source pointer. Must not be NULL. Must not overlap with @p pDst.
 * @param[in]   pSrc2      The source pointer. Must not be NULL. Must not overlap with @p pDst.
 * @param[out]  pDst       The destination pointer. Must not be NULL. Must not overlap with @p pSrc or @p pSrc2.
 * @param[in]   dstLength  The size of the destination data buffer in bytes.
 * @param[in]   length     The number of bytes to XOR.
 * @param[in]   order      The byte order in the destination buffer. This value shall be either
 *                         #MCUXCSSLMEMORY_KEEP_ORDER or #MCUXCSSLMEMORY_REVERSE_ORDER.
 *
 * @return A status code encapsulated in a flow-protection type.
 * @retval #MCUXCSSLMEMORY_STATUS_OK                 The operation was successful.
 * @retval #MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER  A parameter was invalid.
 * @retval #MCUXCSSLMEMORY_STATUS_FAULT              A fault occurred in the execution.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_SecureXOR)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureXOR
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void const * pSrc,
    void const * pSrc2,
    void * pDst,
    uint32_t dstLength,
    uint32_t length,
    uint32_t order
);

/**
 * @brief XORs @p length bytes of data from @p pSrc with a 1-byte @p byteConstant and stores it in @p pDst
 *
 * The implementation is secure in the following aspects:
 * * Random order memory access
 * * Parameter integrity protection: An incorrect parameter checksum makes the function return immediately.
 * * Code flow protection: The function call is protected. Additionally, the result depends on all steps of the calculation.
 * * Buffer overflow protection: No data is written to @p pDst beyond @p dstLength bytes.
 *
 * @param[in]   chk        The parameter checksum, generated with #MCUX_CSSL_PI_PROTECT.
 * @param[in]   pSrc       The source pointer. Must not be NULL. Must not overlap with @p pDst.
 * @param[in]   byteConstant   1-byte constant.
 * @param[out]  pDst       The destination pointer. Must not be NULL. Must not overlap with @p pSrc.
 * @param[in]   dstLength  The size of the destination data buffer in bytes.
 * @param[in]   length     The number of bytes to XOR. Must be different from zero.
 *
 * @return A status code encapsulated in a flow-protection type.
 * @retval #MCUXCSSLMEMORY_STATUS_OK                 The operation was successful.
 * @retval #MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER  A parameter was invalid.
 * @retval #MCUXCSSLMEMORY_STATUS_FAULT              A fault occurred in the execution.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_SecureXORWithConst)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureXORWithConst
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void * pSrc,
    uint8_t byteConstant,
    void * pDst,
    uint32_t dstLength,
    uint32_t length
);


/**
 * @}
 */

/**
 * @}
 */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCSSLMEMORY_SECUREXOR_H */
