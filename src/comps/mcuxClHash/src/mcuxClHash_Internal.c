/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

#include <mcuxClHash.h>
#include <internal/mcuxClHash_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_processedLength_add)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHash_processedLength_add(uint64_t *pLen128, uint64_t addLen)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_processedLength_add);

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Integer wrap is intentional, carry is handled in the next line")
    pLen128[0] += addLen;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
    pLen128[1] += (pLen128[0] < addLen) ? 1U : 0U;

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHash_processedLength_add);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_processedLength_cmp)
MCUX_CSSL_FP_PROTECTED_TYPE (int) mcuxClHash_processedLength_cmp(uint64_t *pLen128, uint64_t cmpLenLow64)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_processedLength_cmp);

    int result = (pLen128[1] != 0U) ? 1 :
                 (pLen128[0] > cmpLenLow64)   ? 1 :
                 (pLen128[0] == cmpLenLow64) ? 0 : -1;

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_processedLength_cmp, result);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_processedLength_toBits)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHash_processedLength_toBits(uint64_t *pLen128)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_processedLength_toBits);

    pLen128[1] = (pLen128[1] << 3U) | (pLen128[0] >> 61U);
    pLen128[0] = pLen128[0] << 3U;

     MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHash_processedLength_toBits);
}
