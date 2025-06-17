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

/** @file  mcuxClMemory_XOR_Internal.h
 *  @brief Memory header for XOR function.
 * This header exposes functions that enable using memory XOR functions.
 */

/**
 * @defgroup mcuxClMemory_XOR_Internal mcuxClMemory_XOR_Internal
 * @brief This function XORs two byte strings of the given length and stores it in the target buffer.
 * @ingroup mcuxClMemory
 * @{
 */

#ifndef MCUXCLMEMORY_XOR_INTERNAL_H_
#define MCUXCLMEMORY_XOR_INTERNAL_H_

#include <mcuxClConfig.h>  // Exported features flags header

#include <mcuxClCore_Platform.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxCsslMemory_Internal_XOR.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @brief This function XORs data from @p pSrc1 and @p pSrc2 and stores the result in @p pDst - internal use only.
 *
 * Operation in place is allowed - one of the input buffer can also be the output buffer.
 *
 * @param[out] pDst        pointer to the destination buffer.
 * @param[in]  pSrc1       pointer to the first source buffer. Can be equal to pDst.
 * @param[in]  pSrc2       pointer to the second source buffer. Can be equal to pDst.
 * @param      length      size (in bytes) to be operated
 * 
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pDst + pSrc1 + pSrc2 + length)
 *
 * @return void
 */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMemory_XOR_int)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_XOR_int
(
    uint8_t *pDst,
    const uint8_t *pSrc1,
    const uint8_t *pSrc2,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMemory_XOR_int);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_XOR(pDst, pSrc1, pSrc2, length));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMemory_XOR_int, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_XOR));
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_XOR_INTERNAL_H_ */

/**
 * @}
 */
