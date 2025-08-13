/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2025 NXP                                                 */
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
 * @file  mcuxCsslMemory_SecureSet.h
 * @brief header file of secure memory set function
 */


#ifndef MCUXCSSLMEMORY_SECURESET_H_
#define MCUXCSSLMEMORY_SECURESET_H_

#include <mcuxCsslMemory_Types.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>

/**
 * @defgroup mcuxCsslMemory_SecureSet mcuxCssl Memory Set
 * @brief Control Flow Protected Memory Set Function
 *
 * @ingroup mcuxCsslMemory
 * @{
 */

/**
 * @defgroup mcuxCsslMemory_SecureSet_Functions mcuxCsslMemory_SecureSet Function Definitions
 * @brief mcuxCsslMemory_SecureSet Function Definitions
 *
 * @ingroup mcuxCsslMemory_SecureSet
 * @{
 */

/**
 * @brief Set @p length bytes of data at @p pDst
 *
 * The implementation is secure in the following aspects:
 * Parameter integrity protection: the function returns immediately in case of an incorrect parameter checksum.
 * Data is first overwritten with random data before being set to the new value
 * Code flow protection: the function call is protected.
 * Buffer overflow protection: no data is written to @p pDst beyond @p bufLength bytes.
 *
 * @param[in]  chk          The parameter checksum, generated with #MCUX_CSSL_PI_PROTECT.
 * @param[in]  pDst         The destination pointer to buffer to be set. Must not be NULL.
 * @param[in]  val          The byte value to be set. 
 * @param[in]  length       The size in bytes to set.
 * @param[in]  bufLength    The buffer size (if bufLength < length, only bufLength bytes are set).
 *
 * @return A status code encapsulated in a flow-protection type.
 * @retval #MCUXCSSLMEMORY_STATUS_OK                 If @p val set @p length times at @p pDst.
 * @retval #MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER  If one of the parameters is invalid.
 * @retval #MCUXCSSLMEMORY_STATUS_FAULT              If a fault was detected, included invalid checksum @p chk.
 * 
 * \implements{REQ_788365}
 *
 * @attention The function uses PRNG, which has to be available and ready for generation.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_SecureSet)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureSet
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void * pDst,
    uint8_t val,
    uint32_t length,
    uint32_t bufLength
);

/**
 * @}
 */

/**
 * @}
 */

#endif /* MCUXCSSLMEMORY_SECURESET_H_ */
