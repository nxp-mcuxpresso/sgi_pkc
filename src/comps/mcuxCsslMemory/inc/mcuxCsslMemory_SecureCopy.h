/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023, 2025 NXP                                            */
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
 * @file  mcuxCsslMemory_SecureCopy.h
 * @brief Include file for secure copy function
 */

#ifndef MCUXCSSLMEMORY_SECURECOPY_H
#define MCUXCSSLMEMORY_SECURECOPY_H

#include <mcuxCsslMemory_Types.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @defgroup mcuxCsslMemory_SecureCopy mcuxCssl Memory Secure Copy
 * @brief Control Flow Protected Secure Memory Copy Function
 *
 * @ingroup mcuxCsslMemory
 * @{
 */

/**
 * @defgroup mcuxCsslMemory_SecureCopy_Functions mcuxCsslMemory_SecureCopy Function Definitions
 * @brief mcuxCsslMemory_SecureCopy Function Definitions
 *
 * @ingroup mcuxCsslMemory_SecureCopy
 * @{
 */

/**
 * @brief Copies @p length bytes of data from @p pSrc to @p pDst
 *
 * The implementation is secure in the following aspects:
 * * Random order memory access
 * * Parameter integrity protection: An incorrect parameter checksum makes the function return immediately.
 * * Code flow protection: The function call is protected. Additionally, the result depends on all steps of the calculation.
 * * Buffer overflow protection: No data is written to @p pDst beyond @p dstLength bytes.
 *
 * @param[in]   chk        The parameter checksum, generated with #MCUX_CSSL_PI_PROTECT.
 * @param[in]   pSrc       The source pointer. Must not be NULL. Must not overlap with @p pDst.
 * @param[out]  pDst       The destination pointer. Must not be NULL. Must not overlap with @p pSrc.
 * @param[in]   dstLength  The size of the destination data buffer in bytes. (if dstLength < length, INVALID_PARAMETER is returned).
 * @param[in]   length     The number of bytes to copy.
 * @param[in]   order      The byte order in the destination buffer. This value shall be either
 *                         #MCUXCSSLMEMORY_KEEP_ORDER or #MCUXCSSLMEMORY_REVERSE_ORDER.
 *
 * @return A status code encapsulated in a flow-protection type.
 * @retval #MCUXCSSLMEMORY_STATUS_OK                 The operation was successful.
 * @retval #MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER  A parameter was invalid.
 * @retval #MCUXCSSLMEMORY_STATUS_FAULT              A fault occurred in the execution.
 * 
 * \implements{REQ_788363}
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_SecureCopy)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureCopy
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void const * pSrc,
    void * pDst,
    uint32_t dstLength,
    uint32_t length,
    uint32_t order
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

#endif /* MCUXCSSLMEMORY_SECURECOPY_H */
