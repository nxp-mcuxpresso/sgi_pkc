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
 * @file  mcuxCsslMemory_SecureXOR.c
 */


#include <stdint.h>
#include <stddef.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>
#include <internal/mcuxCsslMemory_Internal_SecureXOR.h>
#include <mcuxCsslMemory_SecureXOR.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_SecureXOR)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureXOR
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void const * pSrc,
    void const * pSrc2,
    void * pDst,
    uint32_t dstLength,
    uint32_t length,
    uint32_t order
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_SecureXOR,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate)
    );

    /* Backup DI value */
    MCUX_CSSL_DI_INIT(diRefValue);

    MCUX_CSSL_DI_RECORD(xorWithConstSrc, (uint32_t) pSrc);
    MCUX_CSSL_DI_RECORD(xorWithConstSrc2, (uint32_t) pSrc2);
    MCUX_CSSL_DI_RECORD(xorWithConstDst, (uint32_t) pDst);
    MCUX_CSSL_DI_RECORD(xorWithConstLength, (uint32_t) length);

    MCUX_CSSL_FP_FUNCTION_CALL(ret_paramIntegrity,
        MCUX_CSSL_PI_VALIDATE(chk, pSrc, pSrc2, pDst, dstLength, length, order));

    if (MCUXCSSLPARAMINTEGRITY_CHECK_VALID != ret_paramIntegrity)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureXOR, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    if((dstLength < length) || (NULL == pSrc) || (NULL == pSrc2) || ( NULL == pDst) )
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureXOR, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    if (MCUXCSSLMEMORY_KEEP_ORDER == order)
    {
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_SecXOR(pDst, pSrc, pSrc2, length));
    }
    else if (MCUXCSSLMEMORY_REVERSE_ORDER == order)
    {
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_SecXORRev(pDst, pSrc, pSrc2, length));
    }
    else
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureXOR, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    MCUX_CSSL_DI_CHECK_EXIT(mcuxCsslMemory_SecureXOR, diRefValue, MCUXCSSLMEMORY_STATUS_FAULT);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxCsslMemory_SecureXOR, MCUXCSSLMEMORY_STATUS_OK, MCUXCSSLMEMORY_STATUS_FAULT,
        MCUX_CSSL_FP_CONDITIONAL(MCUXCSSLMEMORY_KEEP_ORDER == order, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_SecXOR)),
        MCUX_CSSL_FP_CONDITIONAL(MCUXCSSLMEMORY_REVERSE_ORDER == order, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_SecXORRev)));
}

MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_SecureXORWithConst)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t) mcuxCsslMemory_SecureXORWithConst
(
    mcuxCsslParamIntegrity_Checksum_t chk,
    void * pSrc,
    uint8_t byteConstant,
    void * pDst,
    uint32_t dstLength,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_SecureXORWithConst,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate)
    );

    /* Backup DI value */
    MCUX_CSSL_DI_INIT(diRefValue);

    MCUX_CSSL_DI_RECORD(xorWithConstSrc, (uint32_t) pSrc);
    MCUX_CSSL_DI_RECORD(xorWithConstDst, (uint32_t) pDst);
    MCUX_CSSL_DI_RECORD(xorWithConstLength, (uint32_t) length);

    MCUX_CSSL_FP_FUNCTION_CALL(ret_paramIntegrity,
        MCUX_CSSL_PI_VALIDATE(chk, pSrc, byteConstant, pDst, dstLength, length));

    if (MCUXCSSLPARAMINTEGRITY_CHECK_VALID != ret_paramIntegrity)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureXORWithConst, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    if((dstLength < length) || ( 0u == length) || (NULL == pSrc) || ( NULL == pDst) )
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_SecureXORWithConst, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER);
    }

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_SecXORWithConst(pDst, pSrc, byteConstant, length));

    MCUX_CSSL_DI_CHECK_EXIT(mcuxCsslMemory_SecureXORWithConst, diRefValue, MCUXCSSLMEMORY_STATUS_FAULT);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxCsslMemory_SecureXORWithConst, MCUXCSSLMEMORY_STATUS_OK, MCUXCSSLMEMORY_STATUS_FAULT,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_SecXORWithConst));
}
