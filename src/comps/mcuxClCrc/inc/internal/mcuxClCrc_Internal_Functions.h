/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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
 * @file  mcuxClCrc_Internal_Functions.h
 * @brief CRC internal functions of the mcuxClCrc component
 */

#ifndef MCUXCLCRC_INTERNAL_FUNCTIONS_H_
#define MCUXCLCRC_INTERNAL_FUNCTIONS_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClCrc_Internal_Constants.h>
#include <internal/mcuxClSession_Internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClCrc_Internal_Functions mcuxClCrc_Internal_Functions
 * @brief Driver layer of the @ref mcuxClCrc component
 * @ingroup mcuxClCrc
 * @{
 */

/**
 * @defgroup mcuxClCrc_Internal_Functions mcuxClCrc_Internal_Functions
 * @brief Defines the CRC internal functions of component @ref mcuxClCrc
 * @ingroup mcuxClCrc_Internal_Functions
 * @{
 */

/**
 * @brief Compute 16-bit CRC checksum of a given byte string with a given seed
 *        and the platform-specified 16-bit CRC polynomial
 *
 * @param[in] pBytes  pointer to the byte string
 * @param     length  length (in bytes) of the string
 * @param     seed16  16-bit seed
 *
 * @post
 *  - Data Integrity: Expunge(pBytes + length)
 *
 * @return A code-flow protected error code (see @ref mcuxCsslFlowProtection)
 * @retval #crcResult  16-bit CRC checksum  (without applying the output mask)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_Internal_updateCRC16)
MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClCrc_Internal_updateCRC16(const uint8_t *pBytes, uint32_t length, uint16_t seed16);

/**
 * @brief Compute 16-bit CRC checksum of a given byte string with a given seed
 *        and the platform-specified 16-bit CRC polynomial
 *
 * @param[in] bufSrc  Pointer to the buffer that contains the string.
 * @param     length  length (in bytes) of the string
 * @param     seed16  16-bit seed
 *
 * @post
 *  -  Data Integrity: Expunge(bufSrc + length)
 *
 * @return A code-flow protected error code (see @ref mcuxCsslFlowProtection)
 * @retval #crcResult  16-bit CRC checksum  (without applying the output mask)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_Internal_updateCRC16_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClCrc_Internal_updateCRC16_buffer(mcuxCl_InputBuffer_t bufSrc, uint32_t length, uint16_t seed16);

/**
 * @brief Identical as mcuxClCrc_Internal_updateCRC16 except, the CRC module has to be preconfigured by the caller.
 *
 * @param[in] pBytes  pointer to the byte string
 * @param     length  length (in bytes) of the string
 *
 * @pre
 *  - The CRC module is already configured.
 * @post
 *  - Data Integrity: Expunge(pBytes + length)
 *
 * @return A code-flow protected error code (see @ref mcuxCsslFlowProtection)
 * @retval #crcResult  16-bit CRC checksum  (without applying the output mask)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_Drv_updateCRC16)
MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClCrc_Drv_updateCRC16(const uint8_t *pBytes, uint32_t length);

/**
 * @brief Identical as mcuxClCrc_Internal_updateCRC16 except, the CRC module has to be preconfigured by the caller.
 *
 * @param[in] bufSrc  Pointer to the buffer that contains the string.
 * @param     length  length (in bytes) of the string
 *
 * @pre
 *  - The CRC module is already configured.
 * @post
 *  - Data Integrity: Expunge(bufSrc + length)
 *
 * @return A code-flow protected error code (see @ref mcuxCsslFlowProtection)
 * @retval #crcResult  16-bit CRC checksum  (without applying the output mask)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_Drv_updateCRC16_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClCrc_Drv_updateCRC16_buffer(mcuxCl_InputBuffer_t bufSrc, uint32_t length);

/**
 * @brief Compute 32-bit CRC checksum of a given byte string with a given seed
 *        and the platform-specified 32-bit CRC polynomial
 *
 * @param[in] pBytes  pointer to the byte string
 * @param     length  length (in bytes) of the string
 * @param     seed16  32-bit seed
 *
 * @post
 *  - Data Integrity: Expunge(pBytes + length)
 *
 * @return A code-flow protected error code (see @ref mcuxCsslFlowProtection)
 * @retval #crcResult  32-bit CRC checksum  (without applying the output mask)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_Internal_updateCRC32)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClCrc_Internal_updateCRC32(const uint8_t *pBytes, uint32_t length, uint32_t seed32);

/**
 * @brief Compute 32-bit CRC checksum of a given byte string with a given seed
 *        and the platform-specified 32-bit CRC polynomial
 *
 * @param[in] bufSrc  Pointer to the buffer that contains the string.
 * @param     length  length (in bytes) of the string
 * @param     seed16  32-bit seed
 *
 * @post
 *  - Data Integrity: Expunge(bufSrc + length)
 *
 * @return A code-flow protected error code (see @ref mcuxCsslFlowProtection)
 * @retval #crcResult  32-bit CRC checksum  (without applying the output mask)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_Internal_updateCRC32)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClCrc_Internal_updateCRC32_buffer(mcuxCl_InputBuffer_t bufSrc, uint32_t length, uint32_t seed32);

/**
 * @brief Identical as mcuxClCrc_Internal_updateCRC32 except, the CRC module has to be preconfigured by the caller.
 *
 * @param[in] pBytes  pointer to the byte string
 * @param     length  length (in bytes) of the string
 *
 * @pre
 *  - The CRC module is already configured.
 * @post
 *  - Data Integrity: Expunge(pBytes + length)
 *
 * @return A code-flow protected error code (see @ref mcuxCsslFlowProtection)
 * @retval #crcResult  32-bit CRC checksum  (without applying the output mask)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_Drv_updateCRC32)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClCrc_Drv_updateCRC32(const uint8_t *pBytes, uint32_t length);

/**
 * @brief Identical as mcuxClCrc_Internal_updateCRC32_buffer except, the CRC module has to be preconfigured by the caller.
 *
 * @param[in] bufSrc  Pointer to the buffer that contains the string.
 * @param     length  length (in bytes) of the string
 *
 * @pre
 *  - The CRC module is already configured.
 * @post
 *  - Data Integrity: Expunge(bufSrc + length)
 *
 * @return A code-flow protected error code (see @ref mcuxCsslFlowProtection)
 * @retval #crcResult  32-bit CRC checksum  (without applying the output mask)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_Drv_updateCRC32_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClCrc_Drv_updateCRC32_buffer(mcuxCl_InputBuffer_t bufSrc, uint32_t length);

/**
 * @brief Computes the CRC for a context struct (without the CRC value member) and saves it in the struct.
 *
 * @param[in,out]  pCtx            Pointer to the context struct (word-aligned).
 * @param          contextSize     Size of the context struct in bytes (including the CRC value member).
 *
 * @pre
 *  -  CRC member needs to be first member of a struct with size of 32 bits.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_computeContextCrc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCrc_computeContextCrc(void* pCtx, uint32_t contextSize);

/**
 * @brief Verifies the CRC of a context struct.
 *
 * The function computes the CRC for a context struct (without the CRC value member) and checks if it is equal
 * to the saved CRC value within the struct.
 *
 * @param[in]  session         Session handle
 * @param[in]  pCtx            Pointer to the context struct (word-aligned).
 * @param      contextSize     Size of the context struct in bytes (including the CRC value member).
 *
 * @pre
 *  -  CRC member needs to be first member of a struct with size of 32 bits.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCrc_verifyContextCrc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCrc_verifyContextCrc(mcuxClSession_Handle_t session, void* pCtx, uint32_t contextSize);


/**
 * @}
 */ /* mcuxClCrc_Internal_Functions */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLCRC_INTERNAL_FUNCTIONS_H_ */
