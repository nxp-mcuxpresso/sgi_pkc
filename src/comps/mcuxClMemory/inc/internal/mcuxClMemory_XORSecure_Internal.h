/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

/** @file  mcuxClMemory_XORSecure_Internal.h
 *  @brief Memory header for secure XOR function.
 * This header exposes functions that enable secure memory XOR function.
 */

/**
 * @defgroup mcuxClMemory_XOR_Secure_Internal mcuxClMemory_XOR_Secure_Internal
 * @brief This function performs XOR for 2 memory buffers in a secure way
 * when a secure XOR is available.
 * @ingroup mcuxClMemory
 * @{
 */

#ifndef MCUXCLMEMORY_XORSECURE_INTERNAL_H_
#define MCUXCLMEMORY_XORSECURE_INTERNAL_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClMemory_Constants.h>
#include <mcuxClMemory_Types.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClMemory_Xor.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @brief This function XORs data from @p pSrc1 and @p pSrc2 in a secure way
 *        when a secure XOR is available and stores the result in @p pDst - internal use only.
 *
 * Operation in place is allowed - one of the input buffer can also be the output buffer.
 *
 * @param[out] pDst        pointer to the destination buffer.
 * @param[in]  pSrc1       pointer to the first source buffer.
 * @param[in]  pSrc2       pointer to the second source buffer.
 * @param      length      size (in bytes) to be operated
 * 
 * @pre
 *  - pDst should not overlap with any of the source buffers
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pDst + pSrc1 + pSrc2 + length)
 *
 * @return void
 */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMemory_XOR_secure_int)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_XOR_secure_int
(
    uint8_t *pDst,
    const uint8_t *pSrc1,
    const uint8_t *pSrc2,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMemory_XOR_secure_int);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_xor(pDst, pSrc1, pSrc2, length, length));
    MCUX_CSSL_DI_EXPUNGE(xorParamsDst /* Not used */, (uint32_t) pDst);
    MCUX_CSSL_DI_EXPUNGE(xorParamsSrc /* Not used */, (uint32_t) pSrc1);
    MCUX_CSSL_DI_EXPUNGE(xorParamsSrc /* Not used */, (uint32_t) pSrc2);
    MCUX_CSSL_DI_EXPUNGE(xorParamsLength /* Not used */, (uint32_t) length);
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMemory_XOR_secure_int, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_xor));
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_XORSECURE_INTERNAL_H_ */

/**
 * @}
 */
