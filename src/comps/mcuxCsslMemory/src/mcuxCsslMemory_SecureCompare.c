/*--------------------------------------------------------------------------*/
/* Copyright 2020-2026 NXP                                                  */
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
 * @file  mcuxCsslMemory_SecureCompare.c
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>
#include <mcuxCsslMemory_SecureCompare.h>
#include <internal/mcuxCsslMemory_Internal_SecureCompare.h>
#include <internal/mcuxCsslMemory_Internal_SecureCompare_arm_asm.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_SecureCompare)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureCompare
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void const * pLhs,
    void const * pRhs,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_SecureCompare,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate)
    );

    /* Backup DI value */
    MCUX_CSSL_DI_INIT(diRefValue);  /* TODO: harmonize usage with mcuxCsslMemory_Compare */
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_SecureCompare_Params, pLhs);
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_SecureCompare_Params, pRhs);
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_SecureCompare_Params, length);

    MCUX_CSSL_FP_FUNCTION_CALL(ret_paramIntegrity,
        MCUX_CSSL_PI_VALIDATE(chk, pLhs, pRhs, length));

    if (MCUXCSSLPARAMINTEGRITY_CHECK_VALID != ret_paramIntegrity)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureCompare, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    if((pLhs == pRhs) || (NULL == pLhs) || (NULL == pRhs))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureCompare, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    if((0U == length)) 
    {
        MCUX_CSSL_DI_EXPUNGE(mcuxCsslMemory_SecureCompare_Params, pLhs);  // Balance the SC
        MCUX_CSSL_DI_EXPUNGE(mcuxCsslMemory_SecureCompare_Params, pRhs);  // Balance the SC
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureCompare, MCUXCSSLMEMORY_STATUS_ZERO_LENGTH);
    }

    MCUX_CSSL_FP_FUNCTION_CALL(retval, mcuxCsslMemory_Int_SecComp_arm_asm(pLhs, pRhs, length));
    MCUX_CSSL_DI_EXPUNGE(mcuxCsslMemory_SecureCompare_Status, retval);

    MCUX_CSSL_DI_CHECK_EXIT(mcuxCsslMemory_SecureCompare, diRefValue, MCUXCSSLMEMORY_STATUS_FAULT);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(
        mcuxCsslMemory_SecureCompare, 
        retval,
        MCUXCSSLMEMORY_STATUS_FAULT,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_SecComp_arm_asm)
    );
}
