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
 * @file  mcuxCsslMemory_SecureSet.c
 * @brief mcuxCsslMemory: implementation of secure memory set function
 */


#include <stddef.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslSecureCounter.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>
#include <internal/mcuxCsslMemory_Internal_SecureSet.h>
#include <mcuxCsslMemory_SecureSet.h>
#include <internal/mcuxClPrng_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_SecureSet)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureSet
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void * pDst,
    uint8_t val,
    uint32_t length,
    uint32_t bufLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_SecureSet,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate)
    );
    
    /* Backup DI value */
    MCUX_CSSL_DI_INIT(diRefValue);
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_SecureSet_params, pDst);

    MCUX_CSSL_FP_FUNCTION_CALL(ret_paramIntegrity,
        MCUX_CSSL_PI_VALIDATE(chk, pDst, val, length, bufLength));

    if (MCUXCSSLPARAMINTEGRITY_CHECK_VALID != ret_paramIntegrity)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureSet, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    if (NULL == pDst)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureSet, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    uint8_t *p8Dst = (uint8_t *) pDst; // needs to be aligned
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()
    uint32_t setLen = bufLength < length ? bufLength : length;
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_SecureSet_params, setLen);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(p8Dst, setLen));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_SecSet(p8Dst, val, setLen));

    MCUX_CSSL_DI_CHECK_EXIT(mcuxCsslMemory_SecureSet, diRefValue, MCUXCSSLMEMORY_STATUS_FAULT);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureSet, MCUXCSSLMEMORY_STATUS_OK,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_SecSet));
}
