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
 * @file  mcuxCsslMemory_Set.c
 * @brief mcuxCsslMemory: implementation of memory set function
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslMemory.h>

#include <internal/mcuxCsslMemory_Internal_Set.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_Int_Set)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_Set
(
    uint8_t * pDst,
    uint8_t val,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Int_Set);

    uint32_t wordVal = ((uint32_t)val << 24) | ((uint32_t)val << 16) | ((uint32_t)val << 8) | (uint32_t)val;

    /* DI protect val and wordVal */
    MCUX_CSSL_DI_RECORD(memSetVal, 2U * wordVal);

    uint32_t currentLen = 0u;
    const uint32_t cpuWordSize = sizeof(uint32_t);

    uint8_t *p8Dst = pDst;

    const uint8_t *p8End = &(((const uint8_t *) pDst)[length]);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("We use p32End only for comparison and not for data access, so it does not need to be aligned.")
    const uint32_t *p32End = (const uint32_t *) p8End;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

    MCUX_CSSL_FP_LOOP_DECL(FirstByteLoop);
    MCUX_CSSL_FP_LOOP_DECL(SecondByteLoop);
    MCUX_CSSL_FP_LOOP_DECL(WordLoop);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("Typecast pointer to integer to check address for alignment")
    while ((0u != ((uint32_t) p8Dst & (cpuWordSize - 1u))) && (currentLen < length) && (p8Dst < p8End))
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(p8Dst);
        MCUX_CSSL_ANALYSIS_COVERITY_START_FALSE_POSITIVE(INTEGER_OVERFLOW, "p8Dst will be in the valid range pDst[0 ~ length].")
        *p8Dst = val;
        MCUX_CSSL_FP_LOOP_ITERATION(FirstByteLoop);
        MCUX_CSSL_DI_DONOTOPTIMIZE(p8Dst);
        *p8Dst = val;
        p8Dst++;
        currentLen++;
        MCUX_CSSL_ANALYSIS_COVERITY_STOP_FALSE_POSITIVE(INTEGER_OVERFLOW)
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("p8Dst is CPU word-aligned after the previous loop")
    uint32_t *p32Dst = (uint32_t *) p8Dst;  /* p8Dst is CPU word-aligned after the previous loop. */
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

    if(cpuWordSize <= length)
    {
        while ((currentLen <= (length - cpuWordSize)) && (p32Dst < p32End))
        {
            MCUX_CSSL_DI_DONOTOPTIMIZE(p32Dst);
            MCUX_CSSL_ANALYSIS_COVERITY_START_FALSE_POSITIVE(INTEGER_OVERFLOW, "p32Dst will be in the valid range pDst[0 ~ length].")
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("p8Dst is CPU word-aligned after the previous loop")
            *p32Dst = wordVal;
            MCUX_CSSL_FP_LOOP_ITERATION(WordLoop);
            MCUX_CSSL_DI_DONOTOPTIMIZE(p32Dst);
            *p32Dst = wordVal;
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

            p32Dst++;
            currentLen += cpuWordSize;
            MCUX_CSSL_ANALYSIS_COVERITY_STOP_FALSE_POSITIVE(INTEGER_OVERFLOW)
        }
    }

    p8Dst = (uint8_t *) p32Dst;
    while ((currentLen < length) && (p8Dst < p8End))
    {
        MCUX_CSSL_DI_DONOTOPTIMIZE(p8Dst);
        MCUX_CSSL_ANALYSIS_COVERITY_START_FALSE_POSITIVE(INTEGER_OVERFLOW, "p8Dst will be in the valid range pDst[0 ~ length].")
        *p8Dst = val;
        MCUX_CSSL_FP_LOOP_ITERATION(SecondByteLoop);
        MCUX_CSSL_DI_DONOTOPTIMIZE(p8Dst);
        *p8Dst = val;
        p8Dst++;
        currentLen++;
        MCUX_CSSL_ANALYSIS_COVERITY_STOP_FALSE_POSITIVE(INTEGER_OVERFLOW)
    }

    /* Expunge the protected input parameters: p8Dst is equal to pDst + length */
    MCUX_CSSL_DI_EXPUNGE(memorySetParam, p8Dst);

    /* Expunge 2 * wordVal */
    MCUX_CSSL_DI_EXPUNGE(memSetVal, wordVal);
    MCUX_CSSL_DI_EXPUNGE(memSetVal, ((uint32_t)val << 24) | ((uint32_t)val << 16) | ((uint32_t)val << 8) | (uint32_t)val);


    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("pointer cast to integer for alignment check")
    MCUX_CSSL_ANALYSIS_COVERITY_START_FALSE_POSITIVE(INTEGER_OVERFLOW, "modular arithmetic, mod 4")
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t noOfBytesToAlignment = ((0u - ((uint32_t) pDst)) % cpuWordSize));
    MCUX_CSSL_ANALYSIS_COVERITY_STOP_FALSE_POSITIVE(INTEGER_OVERFLOW)
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()

    MCUX_CSSL_FP_COUNTER_STMT(uint32_t firstByteIteration = (length > noOfBytesToAlignment)
                             ? noOfBytesToAlignment
                             : length);
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t wordIteration = (length > firstByteIteration)
                             ? ((length - firstByteIteration) / cpuWordSize)
                             : 0u);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxCsslMemory_Int_Set,
        MCUX_CSSL_FP_LOOP_ITERATIONS(FirstByteLoop, firstByteIteration),
        MCUX_CSSL_FP_LOOP_ITERATIONS(WordLoop, wordIteration),
        MCUX_CSSL_FP_LOOP_ITERATIONS(SecondByteLoop, length - (wordIteration * cpuWordSize) - firstByteIteration));
}

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
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Set);

    uint32_t copyLen = bufLength < length ? bufLength : length;

    /* Backup DI value */
    MCUX_CSSL_DI_INIT(diRefValue);
    MCUX_CSSL_DI_RECORD(memorySetParam, pDst);
    MCUX_CSSL_DI_RECORD(memorySetParam, copyLen);

    MCUX_CSSL_FP_FUNCTION_CALL(retCode_paramIntegrityValidate, MCUX_CSSL_PI_VALIDATE(chk, pDst, val, length, bufLength));

    if (MCUXCSSLPARAMINTEGRITY_CHECK_VALID != retCode_paramIntegrityValidate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Set, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    MCUXCLCORE_DONOTOPTIMIZE(copyLen);

    if(copyLen > bufLength || copyLen > length)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Set, MCUXCSSLMEMORY_STATUS_FAULT);
    }

    if (NULL == pDst)
    {
        MCUX_CSSL_DI_EXPUNGE(memorySetParam, pDst);
        MCUX_CSSL_DI_EXPUNGE(memorySetParam, copyLen);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Set, MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER,
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate));
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    uint8_t *p8Dst = (uint8_t *) pDst;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxCsslMemory_Int_Set(p8Dst, val, copyLen));

    MCUX_CSSL_DI_CHECK_EXIT(mcuxCsslMemory_Set, diRefValue, MCUXCSSLMEMORY_STATUS_FAULT);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxCsslMemory_Set, MCUXCSSLMEMORY_STATUS_OK,
                                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslParamIntegrity_Validate),
                                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Int_Set));
}
