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

/** @file  mcuxClMemory_Clear_Internal.h
 *  @brief Memory header for clear function.
 * This header exposes functions that enable using memory clear function.
 */


/**
 * @defgroup mcuxClMemory_Clear_Internal mcuxClMemory_Clear_Internal
 * @brief This function clears a memory region.
 * @ingroup mcuxClMemory
 * @{
 */


#ifndef MCUXCLMEMORY_CLEAR_INTERNAL_H_
#define MCUXCLMEMORY_CLEAR_INTERNAL_H_

#include <mcuxClConfig.h>  // Exported features flags header

#include <mcuxClCore_Platform.h>
#include <mcuxClMemory_Constants.h>
#include <mcuxClMemory_Types.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslMemory.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @brief Clears all bytes of the memory buffer - internal use only.
 *
 * @param[out]  pDst       pointer to the buffer to be set.
 * @param       length     size (in bytes) to be set.
 *
 * @pre
 *  - For better performance and security, please use aligned pointers, and lengths multiple of word size.
 * @post
 *  - Data Integrity: Expunge(pDst + length)
 *
 * @return void
 */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMemory_clear_int)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMemory_clear_int
(
    uint8_t * pDst,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMemory_clear_int);

    (void)mcuxCsslMemory_Clear(
        MCUX_CSSL_PI_PROTECT(pDst, length, length),
        pDst,
        length,
        length);// For internal usage, only OK return is expected
    MCUX_CSSL_DI_EXPUNGE(identifier /* Not used */, (uint32_t) pDst + length);  // Unbalance the SC
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMemory_clear_int);
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_CLEAR_INTERNAL_H_ */

/**
 * @}
 */
