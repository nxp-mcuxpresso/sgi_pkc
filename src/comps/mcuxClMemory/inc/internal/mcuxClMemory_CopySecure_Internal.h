/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

/** @file  mcuxClMemory_CopySecure_Internal.h
 *  @brief Memory header for copy functions.
 * This header exposes functions that enable secure memory copy function.
 */

/**
 * @defgroup mcuxClMemory_Copy_Secure_Internal mcuxClMemory_Copy_Secure_Internal
 * @brief This function securely copies a memory region from @p src to @p dst when a secure copy is available.
 * @ingroup mcuxClMemory
 * @{
 */

#ifndef MCUXCLMEMORY_COPYSECURE_INTERNAL_H_
#define MCUXCLMEMORY_COPYSECURE_INTERNAL_H_

#include <mcuxClConfig.h>  // Exported features flags header

#include <mcuxClCore_Platform.h>
#include <mcuxClMemory_Constants.h>
#include <mcuxClMemory_Types.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslMemory.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @brief Copies a memory buffer to another location with security against fault and SPA - internal use only.
 *  
 * @param[out] pDst        pointer to the buffer to be copied to.
 * @param[in]  pSrc        pointer to the buffer to copy.
 * @param      length      size (in bytes) to be copied.
 * 
 * @pre
 *  - @p pDst and @p pSrc must not overlap.
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pSrc + pDst + length)
 *
 * @return void
 */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMemory_copy_secure_int)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_copy_secure_int
(
    uint8_t * pDst,
    uint8_t const * pSrc,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMemory_copy_secure_int);

    (void)mcuxCsslMemory_Copy(MCUX_CSSL_PI_PROTECT(pSrc, pDst, length, length),
                             pSrc, pDst, length, length); // For internal usage, only OK return is expected
    // Unbalance the SC
    MCUX_CSSL_DI_EXPUNGE(copyParamsSrc /* Not used */, (uint32_t) pSrc);
    MCUX_CSSL_DI_EXPUNGE(copyParamsDst /* Not used */, (uint32_t) pDst);
    MCUX_CSSL_DI_EXPUNGE(copyParamsLength /* Not used */, length);
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMemory_copy_secure_int);
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_COPYSECURE_INTERNAL_H_ */

/**
 * @}
 */
