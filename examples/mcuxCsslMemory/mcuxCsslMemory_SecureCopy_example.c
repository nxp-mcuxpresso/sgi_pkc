/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023, 2025 NXP                                            */
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
 * @example  mcuxCsslMemory_SecureCopy_example.c
 * @brief Example for the secure copy function
 */


#include <stdbool.h>
#include <stdint.h>
#include <mcuxCsslMemory.h>
#include <mcuxCsslMemory_Examples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>


#define BYTELEN_SOURCE 64u
#define BYTELEN_TARGET 80u

/* Array of 0x00 ~ 0x3F */
static const uint32_t source[BYTELEN_SOURCE / (sizeof(uint32_t))] =
{
    0x03020100u, 0x07060504u, 0x0B0A0908u, 0x0F0E0D0Cu,
    0x13121110u, 0x17161514u, 0x1B1A1918u, 0x1F1E1D1Cu,
    0x23222120u, 0x27262524u, 0x2B2A2928u, 0x2F2E2D2Cu,
    0x33323130u, 0x37363534u, 0x3B3A3938u, 0x3F3E3D3Cu
};

bool mcuxCsslMemory_SecureCopy_example(void)
{
    uint8_t target[BYTELEN_TARGET] = {0};

    const uint8_t * pSource = (const uint8_t *) source;
    uint8_t * pTarget = (uint8_t *) target;

    /* Example of mcuxCsslMemory_SecureCopy with KEEP_ORDER. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultSecureCopy, tokenSecureCopy,
        mcuxCsslMemory_SecureCopy(MCUX_CSSL_PI_PROTECT(pSource, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE, MCUXCSSLMEMORY_KEEP_ORDER),
                                 pSource, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE, MCUXCSSLMEMORY_KEEP_ORDER) );
    if (   (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureCopy) != tokenSecureCopy)
        || (MCUXCSSLMEMORY_STATUS_OK != resultSecureCopy))
    {
        return MCUXCSSLMEMORY_EX_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Example of mcuxCsslMemory_SecureCopy with REVERSE_ORDER. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultSecureCopyRev, tokenSecureCopyRev,
        mcuxCsslMemory_SecureCopy(MCUX_CSSL_PI_PROTECT(pSource, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE, MCUXCSSLMEMORY_REVERSE_ORDER),
                                 pSource, pTarget, BYTELEN_TARGET, BYTELEN_SOURCE, MCUXCSSLMEMORY_REVERSE_ORDER) );
    if (   (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureCopy) != tokenSecureCopyRev)
        || (MCUXCSSLMEMORY_STATUS_OK != resultSecureCopyRev))
    {
        return MCUXCSSLMEMORY_EX_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCSSLMEMORY_EX_OK;
}
