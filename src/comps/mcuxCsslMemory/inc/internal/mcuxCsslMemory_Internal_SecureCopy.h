/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @file  mcuxCsslMemory_Internal_SecureCopy.h
 * @brief Internal header of mcuxCsslMemory_Int_SecCopy(Rev)
 */

#ifndef MCUXCSSLMEMORY_INTERNAL_SECURECOPY_H
#define MCUXCSSLMEMORY_INTERNAL_SECURECOPY_H

#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief securely copy byte string - internal use only
 * 
 * This function securely copies byte string of the given length from source
 * to target. It assumes there is no overlapping between buffers at source
 * and target.
 * 
 * @param[out] pTarget  destination address
 * @param[in]  pSource  source address
 * @param      length   byte length of the string to be copied
 * 
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pTarget + pSource + length)
 *
 * @return void
 */
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_SecCopy(
    uint8_t * pTarget,
    const uint8_t * pSource,
    uint32_t length
    );

/**
 * @brief securely copy byte string, with reversed byte order - internal use only
 * 
 * This function securely copies byte string of the given length from source
 * to target, with reversed byte order. It assumes there is no overlapping
 * between buffers at source and target.
 * 
 * @param[out] pTarget  destination address
 * @param[in]  pSource  source address
 * @param      length   byte length of the string to be copied
 * 
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pTarget + pSource + length)
 *
 * @return void
 */
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_SecCopyRev(
    uint8_t * pTarget,
    const uint8_t * pSource,
    uint32_t length
    );


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCSSLMEMORY_INTERNAL_SECURECOPY_H */
