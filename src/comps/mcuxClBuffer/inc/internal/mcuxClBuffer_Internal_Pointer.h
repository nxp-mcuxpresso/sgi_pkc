/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @file  mcuxClBuffer_Internal_Pointer.h
 * @brief Provides the internal API & implementation for the plain C pointer buffer types.
 */

#ifndef MCUXCLBUFFER_INTERNAL_POINTER_H_
#define MCUXCLBUFFER_INTERNAL_POINTER_H_

#include <mcuxClToolchain.h>
#include <mcuxClCore_Platform.h>

#include <mcuxClBuffer.h>
#include <mcuxClBuffer_Pointer.h>

#include <mcuxCsslDataIntegrity.h>

#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>
#include <internal/mcuxClMemory_Copy_Reversed_Internal.h>
#include <internal/mcuxClMemory_CopySecure_Internal.h>
#include <internal/mcuxClMemory_CopySecure_Reversed_Internal.h>
#include <internal/mcuxClBuffer_FeatureConfig.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @defgroup clBufferUsage Buffer read/write functionality
 * @brief Buffer read/write functionality.
 * @ingroup mcuxClBuffer
 */

/**
 * @brief Perform a read from the buffer
 *
 * @param[in]  bufSrc     Input buffer from which the data shall be read.
 * @param      offset     Offset into the buffer at which the read operation shall start.
 * @param[out] pDst       Pointer to the memory location where the data will be stored.
 * @param      byteLength Amount of bytes that will be read.
 *
 * @post
 *  -  Data Integrity: Expunge(pDst + bufSrc + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_read)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength);

/**
 * @brief Perform a word-wise read from the buffer
 *
 * @param[in]  bufSrc     Input buffer from which the data shall be read.
 * @param      offset     Offset into the buffer at which the read operation shall start.
 * @param[out] pDst       Pointer to the aligned memory location where the data will be stored.
 * @param      byteLength Amount of bytes that will be read.
 *
 * @pre
 *  - pDst must be 32-bit aligned.
 * @post
 *  - Data Integrity: Expunge(pDst + bufSrc + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_read_word)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_word(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength);

/**
 * @brief Perform a read with endianess reversal from the buffer
 *
 * @param[in]  bufSrc     Input buffer from which the data shall be read.
 * @param      offset     Offset into the buffer at which the read operation shall start.
 * @param[out] pDst       Pointer to the memory location where the data will be stored.
 * @param      byteLength Amount of bytes that will be read.
 *
 * @post
 *  - Data Integrity: Expunge(pDst + bufSrc + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_read_reverse)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_reverse(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength);

/**
 * @brief Perform a secure read from the buffer
 *
 * @param[in]  bufSrc     Input buffer from which the data shall be read.
 * @param      offset     Offset into the buffer at which the read operation shall start.
 * @param[out] pDst       Pointer to the memory location where the data will be stored.
 * @param      byteLength Amount of bytes that will be read.
 *
 * @post
 *  -  Data Integrity: Expunge(pDst + bufSrc + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_read_secure)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_secure(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength);

/**
 * @brief Perform a secure read with endianess reversal from the buffer
 *
 * @param[in]  bufSrc     Input buffer from which the data shall be read.
 * @param      offset     Offset into the buffer at which the read operation shall start.
 * @param[out] pDst       Pointer to the memory location where the data will be stored.
 * @param      byteLength Amount of bytes that will be read.
 *
 * @post
 *  -  Data Integrity: Expunge(pDst + bufSrc + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_read_secure_reverse)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_secure_reverse(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength);

#ifdef MCUXCLBUFFER_FEATURE_INTERNAL_READ_NO_DEST_INC
/**
 * @brief Write to a SFR register from an input buffer.
 *
 * @param[in]  bufSrc     Input buffer from which the data shall be read.
 * @param      offset     Offset into the buffer at which the read operation shall start.
 * @param[out] pDst       Pointer to the register location where the data will be written.
 *                        This address is not incremented during the whole execution of the function.
 * @param      byteLength Amount of bytes that will be read.
 *
 * @pre
 *  - pDst must be 32-bit aligned.
 *  - Depending on the length and on the alignment of source address, this function might write byte-wisely to the target SFR.
 *    If word access shall be ensured, the addresses shall be aligned and the length shall be a multiple of 4 (CPU word size).
 * @post
 *  - Data Integrity: Expunge(pDst + bufSrc + byteLength + offset)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_read_withoutDestIncrement)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_withoutDestIncrement(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength);
#endif /* MCUXCLBUFFER_FEATURE_INTERNAL_READ_NO_DEST_INC */

/**
 * @brief Perform a write to the buffer
 *
 * @param[out] bufDst     Output buffer to which the data shall be written.
 * @param      offset     Offset into the buffer at which the write operation shall start.
 * @param[in]  pSrc       Pointer to the memory location from where the data will be read.
 * @param      byteLength Amount of bytes that will be written.
 *
 * @post
 *  -  Data Integrity: Expunge(pSrc + bufDst + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_write)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength);

/**
 * @brief Perform a word-wise write to the buffer
 *
 * @param[out] bufDst     Output buffer to which the data shall be written.
 * @param      offset     Offset into the buffer at which the write operation shall start.
 * @param[in]  pSrc       Pointer to the aligned memory location from where the data will be read.
 * @param      byteLength Amount of bytes that will be written.
 *
 * @pre
 *  - pSrc must be 32-bit aligned.
 * @post
 *  - Data Integrity: Expunge(pSrc + bufDst + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_write_word)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write_word(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength);

/**
 * @brief Perform a write with endianess reversal to the buffer
 *
 * @param[out] bufDst     Output buffer to which the data shall be written.
 * @param      offset     Offset into the buffer at which the write operation shall start.
 * @param[in]  pSrc       Pointer to the memory location from where the data will be read.
 * @param      byteLength Amount of bytes that will be written.
 *
 * @post
 *  - Data Integrity: Expunge(pSrc + bufDst + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_write_reverse)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write_reverse(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength);

/**
 * @brief Perform a secure write to the buffer
 *
 * @param[out] bufDst     Output buffer to which the data shall be written.
 * @param      offset     Offset into the buffer at which the write operation shall start.
 * @param[in]  pSrc       Pointer to the memory location from where the data will be read.
 * @param      byteLength Amount of bytes that will be written.
 *
 * @post
 *  - Data Integrity: Expunge(pSrc + bufDst + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_write_secure)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write_secure(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength);

/**
 * @brief Perform a secure write with endianess reversal to the buffer
 *
 * @param[out] bufDst     Output buffer to which the data shall be written.
 * @param      offset     Offset into the buffer at which the write operation shall start.
 * @param[in]  pSrc       Pointer to the memory location from where the data will be read.
 * @param      byteLength Amount of bytes that will be written.
 *
 * @post
 *  - Data Integrity: Expunge(pSrc + bufDst + offset + byteLength)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClBuffer_write_secure_reverse)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write_secure_reverse(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength);

/**
 * @brief Writes the pointer of @p bufSrc plus the @p offset in @p ppDest.
 *
 * @param[in]  bufSrc      Input buffer
 * @param      offset      Offset of the input buffer
 * @param      bufCpuWa    Not used
 * @param[out] ppDest      Pointer-pointer to the destination address
 * @param      byteLength  Not used
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_inputBufferToCPU)
static inline void mcuxClBuffer_inputBufferToCPU(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *bufCpuWa UNUSED_PARAM, const uint8_t **ppDest, uint32_t byteLength UNUSED_PARAM)
{
  *ppDest = (const uint8_t *)bufSrc + offset;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLBUFFER_INTERNAL_POINTER_H_ */
