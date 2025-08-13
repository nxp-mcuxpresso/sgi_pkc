/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @file  mcuxClEcc_EdDSA_Internal_Hash.h
 * @brief internal header for abstracting hash calls in mcuxClEcc EdDSA
 */


#ifndef MCUXCLECC_EDDSA_INTERNAL_HASH_H_
#define MCUXCLECC_EDDSA_INTERNAL_HASH_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClHash_Types.h>
#include <mcuxClHash_Functions.h>
#include <mcuxClHash_Constants.h>

#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClHash_Internal.h>


/******************************************************************************/
/* Macro to compute private key hash and store it in PKC workarea.            */
/* Since the parameter b of both Ed25519 and Ed448 is a multiple of 8,        */
/* byte length of private key hash (= 2b/8) can be derived from               */
/* byte length of private key (= b/8).                                        */
/* Data Integrity: EXPUNGE: buffPrivKey + buffPrivkeyHash + privkeyLen        */
/******************************************************************************/
#define MCUXCLECC_FP_EDDSA_KEYGEN_HASH_PRIVKEY(pSession, hashAlg, buffPrivKey, buffPrivKeyHash, privKeyLen)  \
    do{                                                                                            \
        uint32_t outLength = 0u;                                                                   \
        /* DI balancing of Hash_compute_internal */                                                \
        MCUX_CSSL_DI_RECORD(hashComputeInternalParams, &outLength);                                 \
        MCUXCLPKC_WAITFORFINISH();                                                                  \
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute_internal));               \
        MCUX_CSSL_FP_FUNCTION_CALL(retHash,                                                         \
            mcuxClHash_compute_internal(pSession,                                                   \
                              hashAlg,                                                             \
                              buffPrivKey,                                                         \
                              privKeyLen,                                                          \
                              buffPrivKeyHash,                                                     \
                              &outLength) );                                                       \
        if ((pDomainParams->algoHash->hashSize != outLength) || (MCUXCLHASH_STATUS_OK != retHash))  \
        {                                                                                          \
            MCUXCLSESSION_FAULT(pSession,                                                           \
                                      MCUXCLECC_STATUS_FAULT_ATTACK);                               \
        }                                                                                          \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()                         \
    } while(false)                                                                                 \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()


/******************************************************************************/
/* Macro to compute input hash and store it in PKC workarea.                  */
/* Since the parameter b of both Ed25519 and Ed448 is a multiple of 8,        */
/* byte length of hash (= 2b/8) can be derived from                           */
/* byte length of encoded public key (= b/8).                                 */
/******************************************************************************/
#define MCUXCLECC_FP_EDDSA_SIGN_VERIFY_CALC_HASH(pSession, pCtx, hashAlg, pHashPrefix, hashPrefixLen, buffSignatureR, signatureRLen, pPubKey, pubKeyLen, buffIn, inSize, buffOutput) \
    do{                                                                                                  \
        uint32_t outLength = 0u;                                                                         \
                                                                                                         \
        MCUX_CSSL_DI_RECORD(hashProcess1Params, pCtx);                                                    \
        MCUX_CSSL_DI_RECORD(hashProcess1Params, hashPrefixLen);                                           \
        MCUX_CSSL_DI_RECORD(hashProcess2Params, pCtx);                                                    \
        MCUX_CSSL_DI_RECORD(hashProcess2Params, buffSignatureR);                                          \
        MCUX_CSSL_DI_RECORD(hashProcess2Params, signatureRLen);                                           \
        MCUX_CSSL_DI_RECORD(hashProcess3Params, pCtx);                                                    \
        MCUX_CSSL_DI_RECORD(hashProcess3Params, pubKeyLen);                                               \
        MCUX_CSSL_DI_RECORD(hashProcess4Params, pCtx);                                                    \
        MCUX_CSSL_DI_RECORD(hashProcess4Params, buffIn);                                                  \
        MCUX_CSSL_DI_RECORD(hashProcess4Params, inSize);                                                  \
        MCUX_CSSL_DI_RECORD(hashFinishParams, pCtx);                                                      \
        MCUX_CSSL_DI_RECORD(hashFinishParams, buffOutput);                                                \
        MCUX_CSSL_DI_RECORD(hashFinishParams, &outLength);                                                \
        /* Initialize the hash context */                                                                \
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init));                                 \
        MCUX_CSSL_FP_FUNCTION_CALL(retInitHash,                                                           \
            mcuxClHash_init(pSession,                                                                     \
                            pCtx,                                                                        \
                            hashAlg) );                                                                  \
        if (MCUXCLHASH_STATUS_OK != retInitHash)                                                          \
        {                                                                                                \
            MCUXCLSESSION_FAULT(pSession,                                                                 \
                               MCUXCLECC_STATUS_FAULT_ATTACK);                                            \
        }                                                                                                \
                                                                                                         \
        /* Update hash context with prefix */                                                            \
        {                                                                                                \
            MCUXCLBUFFER_INIT_RO(buffHashPrefix, NULL, pHashPrefix, hashPrefixLen);                       \
            MCUX_CSSL_DI_RECORD(hashProcess1Params, buffHashPrefix);                                      \
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process_internal));                 \
            MCUX_CSSL_FP_FUNCTION_CALL(retProcess1Hash,                                                   \
                mcuxClHash_process_internal(pSession,                                                     \
                                pCtx,                                                                    \
                                buffHashPrefix,                                                          \
                                hashPrefixLen) );                                                        \
            if (MCUXCLHASH_STATUS_OK != retProcess1Hash)                                                  \
            {                                                                                            \
                MCUXCLSESSION_FAULT(pSession,                                                             \
                               MCUXCLECC_STATUS_FAULT_ATTACK);                                            \
            }                                                                                            \
        }                                                                                                \
        /* Update hash context with Renc */                                                              \
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process_internal));                     \
        MCUX_CSSL_FP_FUNCTION_CALL(retProcess2Hash,                                                       \
            mcuxClHash_process_internal(pSession,                                                         \
                              pCtx,                                                                      \
                              buffSignatureR,                                                            \
                              signatureRLen) );                                                          \
        if (MCUXCLHASH_STATUS_OK != retProcess2Hash)                                                      \
        {                                                                                                \
            MCUXCLSESSION_FAULT(pSession,                                                                 \
                               MCUXCLECC_STATUS_FAULT_ATTACK);                                            \
        }                                                                                                \
        /* Update hash context with Qenc */                                                              \
        {                                                                                                \
            MCUXCLBUFFER_INIT_RO(buffPubKey, NULL, pPubKey, pubKeyLen);                                   \
            MCUX_CSSL_DI_RECORD(hashProcess3Params, buffPubKey);                                          \
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process_internal));                 \
            MCUX_CSSL_FP_FUNCTION_CALL(retProcess3Hash,                                                   \
                mcuxClHash_process_internal(pSession,                                                     \
                                  pCtx,                                                                  \
                                  buffPubKey,                                                            \
                                  pubKeyLen) );                                                          \
            if (MCUXCLHASH_STATUS_OK != retProcess3Hash)                                                  \
            {                                                                                            \
                MCUXCLSESSION_FAULT(pSession,                                                             \
                                   MCUXCLECC_STATUS_FAULT_ATTACK);                                        \
            }                                                                                            \
        }                                                                                                \
        /* Update hash context with m' */                                                                \
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process_internal));                     \
        MCUX_CSSL_FP_FUNCTION_CALL(retProcess4Hash,                                                       \
            mcuxClHash_process_internal(pSession,                                                         \
                              pCtx,                                                                      \
                              buffIn,                                                                    \
                              inSize) );                                                                 \
        if (MCUXCLHASH_STATUS_OK != retProcess4Hash)                                                      \
        {                                                                                                \
            MCUXCLSESSION_FAULT(pSession,                                                                 \
                               MCUXCLECC_STATUS_FAULT_ATTACK);                                            \
        }                                                                                                \
                                                                                                         \
        MCUXCLPKC_WAITFORFINISH();                                                                        \
        /* Finalize hash computation */                                                                  \
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish_internal));                      \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(                                                                  \
            mcuxClHash_finish_internal(pSession,                                                          \
                              pCtx,                                                                      \
                              buffOutput,                                                                \
                              &outLength) );                                                             \
        if (pDomainParams->algoHash->hashSize != outLength)                                              \
        {                                                                                                \
            MCUXCLSESSION_FAULT(pSession,                                                                 \
                               MCUXCLECC_STATUS_FAULT_ATTACK);                                            \
        }                                                                                                \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()                               \
    } while(false)                                                                                       \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()


#endif /* MCUXCLECC_EDDSA_INTERNAL_HASH_H_ */
