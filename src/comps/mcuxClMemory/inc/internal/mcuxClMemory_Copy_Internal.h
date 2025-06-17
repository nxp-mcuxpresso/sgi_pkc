/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021, 2023-2024 NXP                                       */
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
#include <mcuxClMemory_Constants.h>
#include <mcuxClMemory_Types.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClMemory_Copy.h>

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

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMemory_copy_int)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_copy_int
(
    uint8_t * pDst,
    uint8_t const * pSrc,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMemory_copy_int);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy(pDst, pSrc, length, length));
    MCUX_CSSL_DI_EXPUNGE(identifier /* Not used */, (uint32_t) pSrc + (uint32_t) pDst + length);  // Balance the SC
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMemory_copy_int, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
}

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
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMemory_copy_withoutDstIncrement_int)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_copy_withoutDstIncrement_int
(
    uint8_t * pDst,
    uint8_t const * pSrc,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMemory_copy_withoutDstIncrement_int);
    
    // TODO CLNS-14121: Implement mcuxClMemory_copy_withoutDstIncrement_int in asm
    const uint8_t *pData = pSrc;

    /* Process byte-wise until word-size aligned buffer remains */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("pointer cast to integer for alignment check")
    while((0u < length) && (0u != (((uint32_t)pData) & (sizeof(uint32_t) - 1u))))
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
    {
        *pDst = *pData;
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Length validity is ensured by the caller.")
        pData++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        length--;
    }

    /* Process word-wise full words of remaining buffer */
    while(sizeof(uint32_t) <= length)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Length validity is ensured by the caller.")
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pData and pDst is 32-bit aligned")
        *((uint32_t*)pDst)  = *(const uint32_t *)pData;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
        pData += sizeof(uint32_t);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        length -= sizeof(uint32_t);
    }

    /* Process byte-wise until the end of Data */
    while(0u < length)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Length validity is ensured by the caller.")
        *pDst = *pData;
        pData++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        length--;
    }

    MCUX_CSSL_DI_EXPUNGE(identifier /* Not used */, (uint32_t) pData + (uint32_t) pDst);   // Balance the SC with initial pDst and incremented pData
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMemory_copy_withoutDstIncrement_int);
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_COPY_INTERNAL_H_ */

/**
 * @}
 */
