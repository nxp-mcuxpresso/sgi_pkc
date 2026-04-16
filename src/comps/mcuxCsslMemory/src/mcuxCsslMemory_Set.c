/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
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
 * @file  mcuxCsslMemory_Set.c
 * @brief mcuxCsslMemory: implementation of memory set function
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslMemory.h>

#include <internal/mcuxCsslMemory_Internal_Set.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_Set)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_Set
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void * pDst,
    uint8_t val,
    uint32_t length,
    uint32_t bufLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Set, 
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate)
    );

    uint32_t setLen = bufLength < length ? bufLength : length;

    /* Backup DI value */
    MCUX_CSSL_DI_INIT(diRefValue);
    MCUX_CSSL_DI_RECORD(memorySetParam, pDst);
    MCUX_CSSL_DI_RECORD(memorySetParam, setLen);

    MCUX_CSSL_FP_FUNCTION_CALL(retCode_paramIntegrityValidate, 
        MCUX_CSSL_PI_VALIDATE(chk, pDst, val, length, bufLength));

    if (MCUXCSSLPARAMINTEGRITY_CHECK_VALID != retCode_paramIntegrityValidate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Set, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    if (NULL == pDst)
    {
        MCUX_CSSL_DI_EXPUNGE(memorySetParam, pDst);
        MCUX_CSSL_DI_EXPUNGE(memorySetParam, setLen);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Set, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    uint8_t *p8Dst = (uint8_t *) pDst;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_Set(p8Dst, val, setLen));

    MCUX_CSSL_DI_CHECK_EXIT(mcuxCsslMemory_Set, diRefValue, MCUXCSSLMEMORY_STATUS_FAULT);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxCsslMemory_Set, MCUXCSSLMEMORY_STATUS_OK, MCUXCSSLMEMORY_STATUS_FAULT,
                                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_Set));
}
