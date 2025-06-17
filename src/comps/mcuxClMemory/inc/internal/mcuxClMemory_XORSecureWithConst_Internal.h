/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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

/** @file  mcuxClMemory_XORSecureWithConst_Internal.h
 *  @brief Memory header for secure XOR with const function.
 * This header exposes functions that enable secure memory XOR with const function.
 */

/**
 * @defgroup mcuxClMemory_XOR_Secure_With_Const_Internal mcuxClMemory_XOR_Secure_With_Const_Internal
 * @brief This function performs XOR of a memory buffer with const in a secure way
 * when a secure XOR is available.
 * @ingroup mcuxClMemory
 * @{
 */

#ifndef MCUXCLMEMORY_XORSECUREWITHCONST_INTERNAL_H_
#define MCUXCLMEMORY_XORSECUREWITHCONST_INTERNAL_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClMemory_Constants.h>
#include <mcuxClMemory_Types.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslFlowProtection.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @brief This function XORs data from @p pSrc with a 1-byte @p byteConstant in a secure way
 *        and stores the result in @p pDst - internal use only.
 *
 * @param[out] pDst         pointer to the destination buffer.
 * @param[in]  pSrc         pointer to the source buffer. Can be equal to pTarget if the length is a multiple of 4
 * @param      byteConstant 1-byte constant.
 * @param      length       size (in bytes) to be operated.
 * 
 * @pre
 *  - if @p pDst overlaps with @p pSrc then @p length must be a multiple of 4
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pDst + pSrc + length)
 *
 * @return void
 */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMemory_XORWithConst_secure_int)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_XORWithConst_secure_int
(
    uint8_t *pDst,
    const uint8_t *pSrc,
    const uint8_t byteConstant,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMemory_XORWithConst_secure_int);
    MCUX_CSSL_DI_EXPUNGE(xorParamsDst /* Not used */, (uint32_t) pDst);
    MCUX_CSSL_DI_EXPUNGE(xorParamsSrc /* Not used */, (uint32_t) pSrc);
    MCUX_CSSL_DI_EXPUNGE(xorParamsLength /* Not used */, (uint32_t) length);
    for(uint32_t i = 0u; i < length; ++i)
    {
        pDst[i] = pSrc[i] ^ byteConstant;
    }
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMemory_XORWithConst_secure_int);
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_XORSECUREWITHCONST_INTERNAL_H_ */

/**
 * @}
 */
