/*--------------------------------------------------------------------------*/
/* Copyright 2020-2023, 2026 NXP                                            */
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
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_Compare_Params, pLhs);
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_Compare_Params, pRhs);
    MCUX_CSSL_DI_RECORD(mcuxCsslMemory_Compare_Params, length);

    MCUX_CSSL_FP_FUNCTION_CALL(ret_paramIntegrity,
        MCUX_CSSL_PI_VALIDATE(chk, pLhs, pRhs, length));

    if( (MCUXCSSLPARAMINTEGRITY_CHECK_VALID != ret_paramIntegrity)) 
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Compare, MCUXCSSLMEMORY_STATUS_FAULT);
    }
    
    if((pLhs == pRhs) || (NULL == pLhs) || (NULL == pRhs))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Compare, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    if((0U == length)) 
    {
        MCUX_CSSL_DI_EXPUNGE(mcuxCsslMemory_Compare_Params, pLhs);  // Balance the SC
        MCUX_CSSL_DI_EXPUNGE(mcuxCsslMemory_Compare_Params, pRhs);  // Balance the SC
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Compare, MCUXCSSLMEMORY_STATUS_ZERO_LENGTH);
    }

    MCUX_CSSL_FP_FUNCTION_CALL(retval, mcuxCsslMemory_Compare_arm_asm(pLhs, pRhs, length));
    MCUX_CSSL_DI_EXPUNGE(mcuxCsslMemory_Compare_Status, retval);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(
      mcuxCsslMemory_Compare,
      retval,
      MCUXCSSLMEMORY_STATUS_FAULT,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare_arm_asm)
    );
}

