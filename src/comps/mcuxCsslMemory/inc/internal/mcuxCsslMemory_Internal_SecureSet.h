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
 * @file  mcuxCsslMemory_Internal_SecureSet.h
 * @brief
 */

#ifndef MCUXCSSLMEMORY_INTERNAL_SECURESET_H
#define MCUXCSSLMEMORY_INTERNAL_SECURESET_H

#include <stdint.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief securely set memory - internal use only
 * 
 * This function securely sets @p length bytes of data at @p pDst
 * 
 * @param[out] pDst      The destination address.
 * @param[in]  val       The byte value to be set.
 * @param      length    Byte length of the string to be set.
 * 
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pDst + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_Int_SecSet)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_SecSet(
    uint8_t * pDst,
    uint8_t val,
    uint32_t length
    );

    
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCSSLMEMORY_INTERNAL_SECURESET_H */
