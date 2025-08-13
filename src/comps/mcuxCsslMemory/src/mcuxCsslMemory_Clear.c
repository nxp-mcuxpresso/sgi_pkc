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
 * @file  mcuxCsslMemory_Clear.c
 * @brief mcuxCsslMemory: implementation of memory clear function
 */


#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslSecureCounter.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslMemory.h>
#include <internal/mcuxCsslMemory_Internal_Set.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_Clear)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_Clear
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void * pDst,
    uint32_t dstLength,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Clear);

    /* Backup DI value */
    MCUX_CSSL_DI_INIT(diRefValue);
    MCUX_CSSL_DI_RECORD(memorySetParam, pDst);
    MCUX_CSSL_DI_RECORD(memorySetParam, length);

    MCUX_CSSL_FP_FUNCTION_CALL(retCode_paramIntegrityValidate, MCUX_CSSL_PI_VALIDATE(chk, pDst, dstLength, length));
    if ((retCode_paramIntegrityValidate != MCUXCSSLPARAMINTEGRITY_CHECK_VALID))
    {
        MCUX_CSSL_DI_EXPUNGE(memorySetParam, pDst);
        MCUX_CSSL_DI_EXPUNGE(memorySetParam, length);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Clear, MCUXCSSLMEMORY_STATUS_FAULT,
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate));
    }

    if(length > dstLength || NULL == pDst)
    {
        MCUX_CSSL_DI_EXPUNGE(memorySetParam, pDst);
        MCUX_CSSL_DI_EXPUNGE(memorySetParam, length);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Clear, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER,
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate));
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    uint8_t *p8Dst = (uint8_t *) pDst;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_Set(p8Dst, 0U, length));

    MCUX_CSSL_DI_CHECK_EXIT(mcuxCsslMemory_Clear, diRefValue, MCUXCSSLMEMORY_STATUS_FAULT);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Clear, MCUXCSSLMEMORY_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_Set));
}
