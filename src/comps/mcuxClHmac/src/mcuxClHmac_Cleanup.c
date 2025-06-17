/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

#include <mcuxClMac.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClHmac_Internal_Functions.h>
#include <internal/mcuxClHmac_Internal_Types.h>
#include <internal/mcuxClMemory_ClearSecure_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSession_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_cleanupOnExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClHmac_cleanupOnExit(
    mcuxClSession_Handle_t session,
    uint32_t *pMemoryToClear,
    size_t wordSizeMemoryToClear,
    size_t wordSizeCpuWaBuffer)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_cleanupOnExit);

    /* Clear sensitive information in cpuWa, if any. */
    if(NULL != pMemoryToClear)
    {
        MCUX_CSSL_DI_RECORD(clearSecureDI, pMemoryToClear);
        MCUX_CSSL_DI_RECORD(clearSecureDI, wordSizeMemoryToClear * sizeof(uint32_t));
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Conversion from word size to byte size cannot wrap.")
        (void)mcuxClMemory_clear_secure_int((uint8_t*)pMemoryToClear, wordSizeMemoryToClear * sizeof(uint32_t));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    /* Free CPU WA in Session */
    mcuxClSession_freeWords_cpuWa(session, wordSizeCpuWaBuffer);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClHmac_cleanupOnExit);
}
