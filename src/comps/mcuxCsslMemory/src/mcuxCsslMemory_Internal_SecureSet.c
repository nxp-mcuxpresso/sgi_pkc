/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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
 * @file  mcuxCsslMemory_Internal_SecureSet.c
 */
#include <stddef.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxCsslPrng_Macros.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_Types.h>
#include <internal/mcuxCsslMemory_Internal_SecureSet.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxCsslMemory_Int_SecSet)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_SecSet
(
    uint8_t * pDst,
    uint8_t val,
    uint32_t length
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxCsslMemory_Int_SecSet);
    
    uint32_t wordVal = ((uint32_t)val << 24u) | ((uint32_t)val << 16u) | ((uint32_t)val << 8u) | (uint32_t)val;

    /* DI protect val and wordVal */
    MCUX_CSSL_DI_RECORD(memSetSecureVal, 2U * wordVal);

    uint32_t currentLen = 0u;
    const uint32_t cpuWordSize = sizeof(uint32_t);
    uint8_t *p8Dst = pDst;

    const uint8_t *p8End = &(((const uint8_t *) pDst)[length]);

    // Randomize the output buffer before setting the value
    uint32_t randomWordValue = MCUXCSSLPRNG_GENERATE_WORD();
    uint8_t randomByteValue = (uint8_t) (randomWordValue & 0xFFu);

    MCUX_CSSL_FP_LOOP_DECL(FirstByteLoop);
    MCUX_CSSL_FP_LOOP_DECL(SecondByteLoop);
    MCUX_CSSL_FP_LOOP_DECL(WordLoop);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("intentional pointer to integer cast to check alignment")
    while ((0u != ((uint32_t) p8Dst & (cpuWordSize - 1u))) && (currentLen < length) && (p8Dst < p8End))
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
    {
        *p8Dst = randomByteValue;
        MCUX_CSSL_DI_DONOTOPTIMIZE(p8Dst);
        MCUX_CSSL_FP_LOOP_ITERATION(FirstByteLoop);
        *p8Dst = val;
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Validity ensured by the caller.")
        p8Dst++;
        currentLen++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("p8Dst is CPU word-aligned after the previous loop.")
    uint32_t *p32Dst = (uint32_t *) p8Dst;  /* p8Dst is CPU word-aligned after the previous loop. */
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    if(cpuWordSize <= length)
    {
        while((currentLen <= (length - cpuWordSize)) && ((uint32_t)p32Dst < (uint32_t)p8End))
        {
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Validity ensured by the caller.")
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("p32Dst has properly aligned and cast was valid")
            *p32Dst = randomWordValue;
            MCUX_CSSL_DI_DONOTOPTIMIZE(p32Dst);
            MCUX_CSSL_FP_LOOP_ITERATION(WordLoop);
            *p32Dst = wordVal;
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
            p32Dst++;
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
            currentLen += cpuWordSize;
        }
        
    }

    p8Dst = (uint8_t *) p32Dst;
    while ((currentLen < length) && ((uint32_t)p8Dst < (uint32_t)p8End))
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Pointer with valid address limited by length parameter. Validity ensured by the caller.")
        *p8Dst = randomByteValue;
        MCUX_CSSL_DI_DONOTOPTIMIZE(p8Dst);
        MCUX_CSSL_FP_LOOP_ITERATION(SecondByteLoop);
        *p8Dst = val;
        p8Dst++;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        currentLen++;
    }

    MCUX_CSSL_FP_COUNTER_STMT(uint32_t noOfBytesToAlignment = ((0u - ((uint32_t) pDst)) & (cpuWordSize - 1u)));
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t firstByteIteration = (length > noOfBytesToAlignment)
                             ? noOfBytesToAlignment
                             : length);
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t wordIteration = (length > firstByteIteration)
                             ? ((length - firstByteIteration) / cpuWordSize)
                             : 0u);

    MCUX_CSSL_DI_EXPUNGE(secureSetParams, p8Dst);

     /* Expunge 2 * wordVal */
    MCUX_CSSL_DI_EXPUNGE(memSetSecureVal, wordVal);
    MCUX_CSSL_DI_EXPUNGE(memSetSecureVal, ((uint32_t)val << 24) | ((uint32_t)val << 16) | ((uint32_t)val << 8) | (uint32_t)val);
    
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxCsslMemory_Int_SecSet,
        MCUX_CSSL_FP_LOOP_ITERATIONS(FirstByteLoop, firstByteIteration),
        MCUX_CSSL_FP_LOOP_ITERATIONS(WordLoop, wordIteration),
        MCUX_CSSL_FP_LOOP_ITERATIONS(SecondByteLoop, length - (wordIteration * cpuWordSize) - firstByteIteration));
}
