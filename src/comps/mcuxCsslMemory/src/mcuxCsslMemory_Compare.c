/*--------------------------------------------------------------------------*/
/* Copyright 2020-2023, 2025 NXP                                            */
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

#include <mcuxCsslMemory.h>
#include <mcuxCsslSecureCounter.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxCsslMemory_Internal_Compare_arm_asm.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_Compare)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_Compare
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void const * pLhs,
    void const * pRhs,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Compare,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate)
    );

    /* Record mcuxCsslMemory_Compare_arm_asm call */
    MCUX_CSSL_DI_RECORD(robustCmp, (uint32_t)pLhs);
    MCUX_CSSL_DI_RECORD(robustCmp, (uint32_t)pRhs);
    MCUX_CSSL_DI_RECORD(robustCmp, length);

    MCUX_CSSL_FP_FUNCTION_CALL(result, MCUX_CSSL_PI_VALIDATE(chk, pLhs, pRhs, length));

    if( (result != MCUXCSSLPARAMINTEGRITY_CHECK_VALID)) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Compare, MCUXCSSLMEMORY_STATUS_FAULT);
    }

   if((NULL == pLhs) || (NULL == pRhs)) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Compare, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    MCUX_CSSL_FP_FUNCTION_CALL(retval, mcuxCsslMemory_Compare_arm_asm(pLhs, pRhs, length));
    MCUX_CSSL_DI_EXPUNGE(robustCmpStatus, retval);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    MCUX_CSSL_FP_FUNCTION_EXIT(
      mcuxCsslMemory_Compare,
      retval,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare_arm_asm)
    );
}

