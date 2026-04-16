/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * @file  mcuxCsslMemory_SecureCopy.c
 */


#include <stdint.h>
#include <stddef.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>
#include <mcuxCsslMemory_SecureCopy.h>
#include <internal/mcuxCsslMemory_Internal_SecureCopy.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_SecureCopy)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureCopy
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void const * pSrc,
    void * pDst,
    uint32_t dstLength,
    uint32_t length,
    uint32_t order
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_SecureCopy,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate)
    );

    /* Backup DI value */
    MCUX_CSSL_DI_INIT(diRefValue);
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_Int_SecCopy_params, pSrc);
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_Int_SecCopy_params, pDst);
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_Int_SecCopy_params, length);

    MCUX_CSSL_FP_FUNCTION_CALL(ret_paramIntegrity,
        MCUX_CSSL_PI_VALIDATE(chk, pSrc, pDst, dstLength, length, order));

    if (MCUXCSSLPARAMINTEGRITY_CHECK_VALID != ret_paramIntegrity)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureCopy, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    MCUX_CSSL_ANALYSIS_COVERITY_START_DEVIATE(MISRA_C_2012_Rule_11_6, "Typecast (void *) to uint for checking overlapping buffers.")
    const uint32_t pSrcTrail = (uint32_t) pSrc + length;
    const uint32_t pDstTrail = (uint32_t) pDst + length;

    if (   (NULL == pSrc) || (NULL == pDst) || (length > dstLength)
        || (((uint32_t) pSrc < pDstTrail) && ((uint32_t) pDst < pSrcTrail)) )  /* overlap */
    MCUX_CSSL_ANALYSIS_COVERITY_STOP_DEVIATE(MISRA_C_2012_Rule_11_6)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureCopy, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    mcuxCsslMemory_Status_t retval = MCUXCSSLMEMORY_STATUS_FAULT;

    if (MCUXCSSLMEMORY_KEEP_ORDER == order)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_SecCopy((uint8_t *) pDst, (const uint8_t *) pSrc, length));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()
        retval = MCUXCSSLMEMORY_STATUS_OK;
    }
    else if (MCUXCSSLMEMORY_REVERSE_ORDER == order)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_SecCopyRev((uint8_t *) pDst, (const uint8_t *) pSrc, length));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()
        retval = MCUXCSSLMEMORY_STATUS_OK;
    }
    else
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureCopy, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    MCUX_CSSL_DI_CHECK_EXIT(mcuxCsslMemory_SecureCopy, diRefValue, MCUXCSSLMEMORY_STATUS_FAULT);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxCsslMemory_SecureCopy, retval, MCUXCSSLMEMORY_STATUS_FAULT,
        MCUX_CSSL_FP_CONDITIONAL(MCUXCSSLMEMORY_KEEP_ORDER == order, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_SecCopy)),
        MCUX_CSSL_FP_CONDITIONAL(MCUXCSSLMEMORY_REVERSE_ORDER == order, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_SecCopyRev))
        );
}
