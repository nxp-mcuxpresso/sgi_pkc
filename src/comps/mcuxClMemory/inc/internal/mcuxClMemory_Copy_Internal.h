/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021, 2023-2025 NXP                                       */
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

/** @file  mcuxClMemory_Copy_Internal.h
 *  @brief Internal memory header for copy functions.
 * This header exposes functions that enable using memory copy function.
 */

/**
 * @defgroup mcuxClMemory_Copy_Internal mcuxClMemory_Copy_Internal
 * @brief This function copies a memory region from @p src to @p dst.
 * @ingroup mcuxClMemory
 * @{
 */

#ifndef MCUXCLMEMORY_COPY_INTERNAL_H_
#define MCUXCLMEMORY_COPY_INTERNAL_H_

#include <mcuxClConfig.h>  // Exported features flags header

#include <mcuxClCore_Platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @brief Copies a memory buffer to another location with security against fault - internal use only.
 *
 * @param[out] pDst        pointer to the buffer to be copied to.
 * @param[in]  pSrc        pointer to the buffer to copy.
 * @param      length      size (in bytes) to be copied.
 *
 * @pre
 *  - @p pDst and @p pSrc must not overlap.
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pDst + pSrc + length)
 *
 * @return void
 */

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMemory_copy_int)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_copy_int
(
    uint8_t * pDst,
    uint8_t const * pSrc,
    uint32_t length
);

#ifdef MCUXCL_FEATURE_INTERNAL_MEMORY_COPY_WITHOUT_DST_INCREMENT
/**
 * @brief Copies a memory buffer to fixed address with security against fault - internal use only.
 *        The destination address is not incremented during the execution of the function.
 *
 * The intended use of this function is to copy the contents of a buffer to a HW SFR,
 * for instance to calculate the CRC of this buffer's content.
 *
 * @param[out] pDst        pointer to the buffer to be copied to.
 * @param[in]  pSrc        pointer to the buffer to copy.
 * @param      length      size (in bytes) to be copied.
 *
 * @pre
 *  - The two buffers must not overlap.
 *  - Depending on the length and on the alignment of source/destination addresses, this function
 *    might write byte-wisely to the destination. If word access shall be ensured, the addresses
 *    shall be aligned and the length shall be a multiple of 4 (CPU word size).
 * @post
 *  -  Data Integrity: Expunge(pSrc + pDst + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMemory_copy_withoutDstIncrement_int)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_copy_withoutDstIncrement_int
(
    uint8_t * pDst,
    uint8_t const * pSrc,
    uint32_t length
);
#endif /* MCUXCL_FEATURE_INTERNAL_MEMORY_COPY_WITHOUT_DST_INCREMENT */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_COPY_INTERNAL_H_ */

/**
 * @}
 */
