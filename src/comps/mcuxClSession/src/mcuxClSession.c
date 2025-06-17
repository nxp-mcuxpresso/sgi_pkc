/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

/** @file  mcuxClSession.c
 *  @brief Implementation of the Session component to deal with session-based
 *  configurations. This file implements the functions declared in
 *  mcuxClSession.h and mcuxClSession_Internal.h */

#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <mcuxClMemory.h>
#include <mcuxClToolchain.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Macros.h>
#include <mcuxClResource.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_ClearSecure_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_allocateWords_cpuWa)
uint32_t* mcuxClSession_allocateWords_cpuWa(
    mcuxClSession_Handle_t pSession,
    uint32_t wordsToAllocate)
{
    uint32_t * pCpuBuffer = NULL;
    const uint32_t usedWords = pSession->cpuWa.used;

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(usedWords, 0u, (UINT32_MAX >> 2u), NULL)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(wordsToAllocate, 0u, (UINT32_MAX >> 2u) - usedWords, NULL)
    const uint32_t expectedUsed = usedWords + wordsToAllocate;

    if (expectedUsed <= pSession->cpuWa.size)
    {
        pCpuBuffer = & (pSession->cpuWa.buffer[usedWords]);
        pSession->cpuWa.used = expectedUsed;

        if (expectedUsed > pSession->cpuWa.dirty)
        {
            pSession->cpuWa.dirty = expectedUsed;
        }
    }
    else
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLSESSION_STATUS_ERROR_MEMORY_ALLOCATION);
    }

    return pCpuBuffer;
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_allocateWords_pkcWa)
uint32_t* mcuxClSession_allocateWords_pkcWa(
    mcuxClSession_Handle_t pSession,
    uint32_t wordsToAllocate)
{
    uint32_t * pPkcBuffer = NULL;
    const uint32_t usedWords = pSession->pkcWa.used;

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(usedWords, 0u, MCUXCLPKC_RAM_SIZE, NULL)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(wordsToAllocate, 0u, MCUXCLPKC_RAM_SIZE - usedWords, NULL)
    const uint32_t expectedUsed = usedWords + wordsToAllocate;

    if (expectedUsed <= pSession->pkcWa.size)
    {
        pPkcBuffer = & (pSession->pkcWa.buffer[usedWords]);
        pSession->pkcWa.used = expectedUsed;

        if (expectedUsed > pSession->pkcWa.dirty)
        {
            pSession->pkcWa.dirty = expectedUsed;
        }
    }
    else
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLSESSION_STATUS_ERROR_MEMORY_ALLOCATION);
    }

    return pPkcBuffer;
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_freeWords_cpuWa)
void mcuxClSession_freeWords_cpuWa(
    mcuxClSession_Handle_t pSession,
    uint32_t wordsToFree)
{
    if(wordsToFree > pSession->cpuWa.used)
    {
        pSession->cpuWa.used = 0u;
    }
    else
    {
        pSession->cpuWa.used -= wordsToFree;
    }
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_freeWords_pkcWa)
void mcuxClSession_freeWords_pkcWa(
    mcuxClSession_Handle_t pSession,
    uint32_t wordsToFree)
{
    if(wordsToFree > pSession->pkcWa.used)
    {
        pSession->pkcWa.used = 0u;
    }
    else
    {
        pSession->pkcWa.used -= wordsToFree;
    }
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_init(
    mcuxClSession_Handle_t pSession,
    uint32_t * const pCpuWaBuffer,
    uint32_t cpuWaLength,
    uint32_t * const pPkcWaBuffer,
    uint32_t pkcWaLength
    )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSession_init);

    if (NULL != pPkcWaBuffer)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("intentional cast to do checks on pointer")
        if (   (0u != ((MCUXCLPKC_WORDSIZE - 1u) & (uint32_t) pPkcWaBuffer))       /* Check pPkcWaBuffer alignment. */
            || ((uint32_t) pPkcWaBuffer < (uint32_t) MCUXCLPKC_RAM_START_ADDRESS)  /* Check pPkcWaBuffer is in PKC workarea. */
            || ((uint32_t) pPkcWaBuffer >= ((uint32_t) MCUXCLPKC_RAM_START_ADDRESS + MCUXCLPKC_RAM_SIZE)) )
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()
        {
            /* We have a session pointer, but we didn't use SESSION_ENTRY in this function.
             * Therefore we use the normal function exit here. */
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSession_init, MCUXCLSESSION_STATUS_ERROR);
        }
    }

    /* Set CPU Wa in session handle */
    pSession->cpuWa.buffer = pCpuWaBuffer;
    pSession->cpuWa.size = cpuWaLength / (sizeof(uint32_t));
    pSession->cpuWa.used = 0u;
    pSession->cpuWa.dirty = 0u;

    /* Set PKC Wa in session handle */
    pSession->pkcWa.buffer = pPkcWaBuffer;
    pSession->pkcWa.size = pkcWaLength / (sizeof(uint32_t));
    pSession->pkcWa.used = 0u;
    pSession->pkcWa.dirty = 0u;


  pSession->apiCall = NULL;

    pSession->jobContext.dmaChannels.input = MCUXCLSESSION_DMACHANNEL_INVALID;
    pSession->jobContext.dmaChannels.output = MCUXCLSESSION_DMACHANNEL_INVALID;
    pSession->jobContext.pUserCallback = NULL;
    pSession->jobContext.pUserData = NULL;
    pSession->jobContext.pCallBackDMA = NULL;
    pSession->jobContext.protectionToken_pCallBackDMA = 0U;
    pSession->jobContext.pCallBackCopro = NULL;
    pSession->jobContext.protectionToken_pCallBackCopro = 0U;

    pSession->randomCfg.ctx = NULL;
    pSession->randomCfg.mode = NULL;
    /* Set the PRNG patch function to un-patch the PRNG */
    pSession->randomCfg.prngPatchFunction = NULL;
    pSession->randomCfg.pCustomPrngState = NULL;

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClSession_init, MCUXCLSESSION_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_setResource)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_setResource(
    mcuxClSession_Handle_t session,
    mcuxClResource_Context_t * pResourceCtx
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSession_setResource);

    session->pResourceCtx = pResourceCtx;

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClSession_setResource, MCUXCLSESSION_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_cleanup)
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_cleanup(
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
  mcuxClSession_Handle_t pSession
)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClSession_cleanup, diRefValue, MCUXCLSESSION_STATUS_FAULT_ATTACK);

    MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_secure_int_CpuWa, pSession->cpuWa.buffer);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_secure_int_CpuWa, (sizeof(uint32_t)) * pSession->cpuWa.dirty);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_secure_int_PkcWa, pSession->pkcWa.buffer);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_secure_int_PkcWa, (sizeof(uint32_t)) * pSession->pkcWa.dirty);

    /* For 32-bit architectures, the maximum number of bytes in the memory is UINT32_MAX, i.e. the maximum number of words is UINT32_MAX / 4 */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pSession->cpuWa.dirty, 0u, (UINT32_MAX >> 2u), MCUXCLSESSION_STATUS_ERROR)

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClMemory_clear_secure_int((uint8_t*)pSession->cpuWa.buffer, (sizeof(uint32_t)) * pSession->cpuWa.dirty)
    );

    /* Reset dirty to used, in case not all memory has been freed (and gets used again). */
    pSession->cpuWa.dirty = pSession->cpuWa.used;

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pSession->pkcWa.dirty, 0u, MCUXCLPKC_RAM_SIZE >> 2u, MCUXCLSESSION_STATUS_ERROR)

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClMemory_clear_secure_int((uint8_t*)pSession->pkcWa.buffer, (sizeof(uint32_t)) * pSession->pkcWa.dirty)
    );

    /* Reset dirty to used, in case not all memory has been freed (and gets used again). */
    pSession->pkcWa.dirty = pSession->pkcWa.used;

    MCUXCLSESSION_EXIT(
      pSession,
      mcuxClSession_cleanup,
      diRefValue,
      MCUXCLSESSION_STATUS_OK,
      MCUXCLSESSION_STATUS_FAULT_ATTACK,
      2U * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_secure_int)
    );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_cleanup_freedWorkareas)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSession_cleanup_freedWorkareas(
  mcuxClSession_Handle_t pSession
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSession_cleanup_freedWorkareas);

    MCUX_CSSL_DI_RECORD(cpu_clear, &pSession->cpuWa.buffer[pSession->cpuWa.used]);
    MCUX_CSSL_DI_RECORD(cpu_clear, (sizeof(uint32_t)) * pSession->cpuWa.dirty - (sizeof(uint32_t)) * pSession->cpuWa.used);
    MCUX_CSSL_DI_RECORD(pkc_clear, &pSession->pkcWa.buffer[pSession->pkcWa.used]);
    MCUX_CSSL_DI_RECORD(pkc_clear, (sizeof(uint32_t)) * pSession->pkcWa.dirty - (sizeof(uint32_t)) * pSession->pkcWa.used);

    /* For 32-bit architectures, the maximum number of bytes in the memory is UINT32_MAX, i.e. the maximum number of words is UINT32_MAX / 4 */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pSession->cpuWa.dirty, 0u, (UINT32_MAX >> 2u), MCUXCLSESSION_STATUS_ERROR)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pSession->cpuWa.used, 0u, pSession->cpuWa.dirty, MCUXCLSESSION_STATUS_ERROR)

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_secure_int(
      (uint8_t*)&pSession->cpuWa.buffer[pSession->cpuWa.used],
      (sizeof(uint32_t)) * pSession->cpuWa.dirty - (sizeof(uint32_t)) * pSession->cpuWa.used
    ));

    /* Reset dirty to used, as the range from used to dirty was cleared before */
    pSession->cpuWa.dirty = pSession->cpuWa.used;

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pSession->pkcWa.dirty, 0u, MCUXCLPKC_RAM_SIZE >> 2u, MCUXCLSESSION_STATUS_ERROR)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pSession->pkcWa.used, 0u, pSession->pkcWa.dirty, MCUXCLSESSION_STATUS_ERROR)

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_secure_int(
      (uint8_t*)&pSession->pkcWa.buffer[pSession->pkcWa.used],
      (sizeof(uint32_t)) * pSession->pkcWa.dirty - (sizeof(uint32_t)) * pSession->pkcWa.used
    ));

    /* Reset dirty to used, in case not all memory has been freed (and gets used again). */
    pSession->pkcWa.dirty = pSession->pkcWa.used;

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(
      mcuxClSession_cleanup_freedWorkareas,
      2U * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_secure_int)
    );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_destroy)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_destroy(
    mcuxClSession_Handle_t pSession
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSession_destroy, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup));

    MCUX_CSSL_FP_FUNCTION_CALL(cleanupStatus, mcuxClSession_cleanup(pSession));
    if(MCUXCLSESSION_STATUS_OK != cleanupStatus)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSession_destroy, MCUXCLSESSION_STATUS_ERROR);
    }

    MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, pSession);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, sizeof(mcuxClSession_Descriptor_t));

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t*)pSession, sizeof(mcuxClSession_Descriptor_t)));

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(
      mcuxClSession_destroy,
      MCUXCLSESSION_STATUS_OK,
      MCUXCLSESSION_STATUS_FAULT_ATTACK,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int)
    );
}



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_setRandom)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_setRandom(
    mcuxClSession_Handle_t session,
    mcuxClRandom_Mode_t randomMode,
    mcuxClRandom_Context_t randomCtx
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSession_setRandom);
    session->randomCfg.ctx = randomCtx;
    session->randomCfg.mode = randomMode;
    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClSession_setRandom, MCUXCLSESSION_STATUS_OK);
}
