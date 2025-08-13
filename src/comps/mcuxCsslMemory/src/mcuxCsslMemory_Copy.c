/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023, 2025 NXP                                            */
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
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxCsslMemory_Internal_Copy_arm_asm.h>
#include <internal/mcuxCsslMemory_Internal_Compare_arm_asm.h>
#include <mcuxCsslDataIntegrity.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_Copy)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_Copy
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void const * pSrc,
    void * pDst,
    uint32_t dstLength,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Copy,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate)
    );

    MCUX_CSSL_FP_FUNCTION_CALL(crcResult, MCUX_CSSL_PI_VALIDATE(chk, pSrc, pDst, dstLength, length));

    if(crcResult != MCUXCSSLPARAMINTEGRITY_CHECK_VALID) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Copy, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    if((NULL == pSrc) || (NULL == pDst) || (length > dstLength)) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Copy, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    /* Record mcuxCsslMemory_Internal_Copy_arm_asm call */
    MCUX_CSSL_DI_RECORD(copyParams, (uint32_t)pSrc);
    MCUX_CSSL_DI_RECORD(copyParams, (uint32_t)pDst);
    MCUX_CSSL_DI_RECORD(copyParams, length);

    uint32_t retval = (uint32_t) MCUXCSSLMEMORY_STATUS_FAULT;

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_Copy_arm_asm(pDst, pSrc, length));

    /*
     * Compare copied data to ensure copy operation performed properly
     */
    MCUX_CSSL_DI_RECORD(compareParams, pDst);
    MCUX_CSSL_DI_RECORD(compareParams, pSrc);
    MCUX_CSSL_DI_RECORD(compareParams, length);
    MCUX_CSSL_FP_FUNCTION_CALL(clRetval, mcuxCsslMemory_Compare_arm_asm(pDst, pSrc, length));
    MCUX_CSSL_DI_EXPUNGE(compareParamsStatus, clRetval);
    if(MCUXCSSLMEMORY_STATUS_EQUAL != clRetval)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Copy, MCUXCSSLMEMORY_STATUS_FAULT);
    }
    else
    {
        retval = MCUXCSSLMEMORY_STATUS_OK;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Copy, retval,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_Copy_arm_asm),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare_arm_asm)
    );
}
