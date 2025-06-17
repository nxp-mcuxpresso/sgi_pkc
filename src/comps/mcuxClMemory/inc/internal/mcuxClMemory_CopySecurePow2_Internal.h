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

/** @file  mcuxClMemory_CopySecurePow2_Internal.h
 *  @brief Memory header for copy functions.
 * This header exposes functions that enable secure memory copy function.
 */

/**
 * @defgroup mcuxClMemory_CopySecurePow2_Internal mcuxClMemory_CopySecurePow2_Internal
 * @brief This function securely copies a memory region from @p src to @p dst when a secure copy is available.
 * @ingroup mcuxClMemory
 * @{
 */

#ifndef MCUXCLMEMORY_COPYSECUREPOW2_INTERNAL_H_
#define MCUXCLMEMORY_COPYSECUREPOW2_INTERNAL_H_

#include <mcuxClConfig.h>  // Exported features flags header

#include <mcuxClCore_Platform.h>
#include <mcuxClMemory_Constants.h>
#include <mcuxClMemory_Types.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClMemory_CopySecure_Internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @brief Copies a memory buffer to another location, with length being a power of 2 and length >= 8,
 *        with security against fault and SPA - internal use only.
 *  
 * @param[out] pDst        pointer to the buffer to be copied to.
 * @param[in]  pSrc        pointer to the buffer to copy.
 * @param      length      size (in bytes) to be copied.
 * 
 * @pre
 *  - @p pDst and @p pSrc must not overlap.
 *  - @p length must be a power of 2 and >= 8
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pSrc + pDst + length)
 * 
 * @return void
 */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMemory_copy_secure_pow2_int)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_copy_secure_pow2_int
(
    uint8_t * pDst,
    uint8_t const * pSrc,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMemory_copy_secure_pow2_int);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(pDst, pSrc, length));
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMemory_copy_secure_pow2_int, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_COPYSECUREPOW2_INTERNAL_H_ */

/**
 * @}
 */
