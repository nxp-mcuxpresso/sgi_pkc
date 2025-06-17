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

/**
 * @file  mcuxCsslMemory_Internal_XOR.h
 * @brief Internal header of mcuxCsslMemory_XOR
 */

#ifndef MCUXCSSLMEMORY_INTERNAL_XOR_H
#define MCUXCSSLMEMORY_INTERNAL_XOR_H

#include <stdint.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief XOR two byte strings - internal use only
 * 
 * This function XORs data from @p pSource and @p pSource2 and stores the result in @p pTarget.
 * Operation in place is allowed - one of the input buffers can also be the output buffer.
 * 
 * @param[out] pTarget        destination address.
 * @param[in]  pSource        first source address. Can be equal to pTarget.
 * @param[in]  pSource2       second source address. Can be equal to pTarget.
 * @param      length         byte length of the string to be processed
 * 
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pTarget + pSource + pSource2 + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_Int_XOR)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_XOR(
    uint8_t *pTarget,
    const uint8_t *pSource,
    const uint8_t *pSource2,
    uint32_t length
);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCSSLMEMORY_INTERNAL_XOR_H */
