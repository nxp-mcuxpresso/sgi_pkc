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
 * @file  mcuxClSession_Internal.h
 * @brief Internal definitions of the mcuxClSession component
 */

#ifndef MCUXCLSESSION_INERNAL_H_
#define MCUXCLSESSION_INERNAL_H_

#include <stddef.h>
#include <mcuxClToolchain.h>
#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSession_Types.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @brief Function to allocate CPU buffer.
 *
 * This function allocates a buffer in CPU workarea specified in @p pSession.
 *
 * @param[in] pSession         Session handle.
 * @param[in] wordsToAllocate  The size of buffer to be allocated, in number of CPU words (uint32_t).
 *
 * @return pointer to the buffer if it is allocated successfully.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSession_allocateWords_cpuWa)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t*) mcuxClSession_allocateWords_cpuWa(mcuxClSession_Handle_t pSession, uint32_t wordsToAllocate);

/**
 * @brief Function to allocate PKC buffer.
 *
 * This function allocates a buffer in PKC workarea specified in @p pSession.
 *
 * The PKC workarea is assumed to be initialized to be PKC-word aligned.
 * However, size of each buffer (allocated from PKC workarea) is in number of CPU words,
 * and address of each buffer is CPU-word aligned, but might be not PKC-word aligned.
 * Callers need to take care if a buffer is PKC-word aligned, if it is used as a PKC operand.
 * For example, the total size of buffer(s) allocated before a PKC operand buffer shall
 * be a multiple of PKC wordsize.
 *
 * @param[in] pSession         Session handle.
 * @param[in] wordsToAllocate  The size of buffer to be allocated, in number of CPU words (uint32_t).
 *
 * @return pointer to the buffer if it is allocated successfully.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSession_allocateWords_pkcWa)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t*) mcuxClSession_allocateWords_pkcWa(mcuxClSession_Handle_t pSession, uint32_t wordsToAllocate);

/**
 * @brief Function to free CPU workarea.
 *
 * This function frees specified words from the tail of used CPU workarea.
 * The space is freed but **not** erased (zeroed).
 *
 * @param[in] pSession     Session handle.
 * @param[in] wordsToFree  The size of CPU workarea to be freed, in number of CPU words (uint32_t)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSession_freeWords_cpuWa)
void mcuxClSession_freeWords_cpuWa(
    mcuxClSession_Handle_t pSession,
    uint32_t wordsToFree
);

/**
 * @brief Function to free PKC workarea.
 *
 * This function frees specified words from the tail of used PKC workarea.
 * The space is freed but **not** erased (zeroed).
 *
 * @param[in] pSession     Session handle.
 * @param[in] wordsToFree  The size of PKC workarea to be freed, in number of CPU words (uint32_t)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSession_freeWords_pkcWa)
void mcuxClSession_freeWords_pkcWa(
    mcuxClSession_Handle_t pSession,
    uint32_t wordsToFree
);

/**
 * @brief Set the Security options in a Crypto Library session.
 *
 * @param  session          Handle for the current CL session.
 * @param  securityOptions  Security options that will be set
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_setSecurityOptions_Internal)
static inline void mcuxClSession_setSecurityOptions_Internal(
  mcuxClSession_Handle_t session,
  mcuxClSession_SecurityOptions_t securityOptions
)
{
/* Unused params*/
    (void) session;
    (void) securityOptions;
}

/**
 * @brief Get the Security options from a Crypto Library session.
 *
 * @param  session          Handle for the current CL session.
 *
 * @return securityOptions  Security options that will be returned
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_getSecurityOptions_Internal)
static inline mcuxClSession_SecurityOptions_t mcuxClSession_getSecurityOptions_Internal(
  mcuxClSession_Handle_t session
)
{
/* Unused param*/
    (void) session;
    return 0u;
}

/**
 * @brief Get the pointer to end of currently used buffer from a Crypto Library session.
 *
 * @param  session          Handle for the current CL session.
 *
 * @return pointer to the end of used buffer, it will be also a start of next allocated buffer.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_getEndOfUsedBuffer_Internal)
static inline uint32_t* mcuxClSession_getEndOfUsedBuffer_Internal(
  mcuxClSession_Handle_t session
)
{
    return (& session->cpuWa.buffer[session->cpuWa.used]);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLSESSION_INERNAL_H_ */
