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
 * @file  mcuxCsslMemory_Internal_SecureXOR.h
 * @brief Internal header of mcuxCsslMemory_SecureXOR
 */

#ifndef MCUXCSSLMEMORY_INTERNAL_SECUREXOR_H
#define MCUXCSSLMEMORY_INTERNAL_SECUREXOR_H

#include <stdint.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief securely XOR a byte string with a 1-byte constant - internal use only
 * 
 * This function securely XORs a byte string of the given length with a given 1-byte constant and
 * stores the result in the target buffer.
 * 
 * @param[out] pTarget  destination address
 * @param[in]  pSource  source address. Can be equal to pTarget if the length is a multiple of 4
 * @param[in]  byteConstant 1-byte constant
 * @param      length   byte length of the string to be processed
 * 
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pTarget + pSource + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_Int_SecXORWithConst)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_SecXORWithConst(
    uint8_t * pTarget,
    const uint8_t * pSource,
    uint8_t byteConstant,
    uint32_t length
    );

/**
 * @brief securely XOR two byte strings - internal use only
 * 
 * This function securely XORs two byte strings of the given length and stores
 * the result in the target buffer.
 * 
 * @param[out] pTarget  destination address
 * @param[in]  pSource  first source address. Can be equal to pTarget.
 * @param[in]  pSource2 second source address
 * @param      length   byte length of the string to be processed
 * 
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pTarget + pSource + pSource2 + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_Int_SecXOR)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_SecXOR(
    uint8_t * pTarget,
    const uint8_t * pSource,
    const uint8_t * pSource2,
    uint32_t length
    );

/**
 * @brief securely XOR two byte strings, and store result in reversed byte order - internal use only
 * 
 * This function securely XORs two byte strings of the given length and stores
 * the result in the target buffer, with reversed byte order.
 * 
 * @param[out] pTarget  destination address
 * @param[in]  pSource  first source address
 * @param[in]  pSource2 second source address
 * @param      length   byte length of the string to be processed
 * 
 * @pre
 *  - pTarget should not overlap with any of the source buffers
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pTarget + pSource + pSource2 + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_Int_SecXORRev)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_SecXORRev(
    uint8_t * pTarget,
    const uint8_t * pSource,
    const uint8_t * pSource2,
    uint32_t length
    );

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCSSLMEMORY_INTERNAL_SECUREXOR_H */
