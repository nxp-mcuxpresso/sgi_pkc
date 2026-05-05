/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
/*--------------------------------------------------------------------------*/

/**
 * @example mcuxClEcc_Weier_KeyValidation_PrivateKey_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClEcc.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

#define MAX_CPUWA_SIZE MCUXCLECC_WEIERECC_PRIVATEKEYVALIDATION_WACPU_SIZE
#define MAX_PKCWA_SIZE MCUXCLECC_WEIERECC_PRIVATEKEYVALIDATION_WAPKC_SIZE_256

// Invalid key d = n
static const uint8_t pPrivKeyData_Invalid[MCUXCLECC_WEIERECC_SECP192R1_SIZE_PRIVATEKEY] __attribute__ ((aligned (4))) =
{
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x99u, 0xDEu, 0xF8u, 0x36u,
    0x14u, 0x6Bu, 0xC9u, 0xB1u, 0xB4u, 0xD2u, 0x28u, 0x31u
};

// Valid key: random  0 < d < n
static const uint8_t pPrivKeyData_Valid[MCUXCLECC_WEIERECC_SECP192R1_SIZE_PRIVATEKEY] __attribute__ ((aligned (4))) =
{
    0x72u, 0xBBu, 0x52u, 0x76u, 0xD8u, 0xA3u, 0x0Fu, 0x37u,
    0x85u, 0x6Eu, 0xB1u, 0x04u, 0x62u, 0xE4u, 0xA2u, 0x56u,
    0x22u, 0xB2u, 0x41u, 0x01u, 0xA1u, 0x23u, 0xDFu, 0x24u
};

/* Example of private key validation for Weierstrass curve secp192r1. */
MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_Weier_KeyValidation_PrivateKey_example)
{
    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    /* Initialize invalid private key for Weierstrass curve secp192r1 */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(privkeyinit_result1, privkeyinit_token1, mcuxClKey_init(
    /* mcuxClSession_Handle_t session    */ session,
    /* mcuxClKey_Handle_t key            */ privKey,
    /* mcuxClKey_Type_t type             */ mcuxClKey_Type_WeierECC_secp192r1_Priv,
    /* const uint8_t * pKeyData         */ pPrivKeyData_Invalid,
    /* uint32_t keyDataLength           */ MCUXCLECC_WEIERECC_SECP192R1_SIZE_PRIVATEKEY));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != privkeyinit_token1) || (MCUXCLKEY_STATUS_OK != privkeyinit_result1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Validate key and expect MCUXCLKEY_STATUS_VALIDATION_FAILED */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyValidate_result1, keyValidate_token1, mcuxClKey_validate(
    /* mcuxClSession_Handle_t pSession   */ session,
    /* mcuxClKey_Validation_t validation */ mcuxClKey_Validation_WeierECC_PrivateKey,
    /* mcuxClKey_Handle_t key */            privKey));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_validate) != keyValidate_token1) || (MCUXCLKEY_STATUS_VALIDATION_FAILED != keyValidate_result1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Initialize valid private key for Weierstrass curve secp192r1 */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(privkeyinit_result2, privkeyinit_token2, mcuxClKey_init(
    /* mcuxClSession_Handle_t session    */ session,
    /* mcuxClKey_Handle_t key            */ privKey,
    /* mcuxClKey_Type_t type             */ mcuxClKey_Type_WeierECC_secp192r1_Priv,
    /* const uint8_t * pKeyData         */ pPrivKeyData_Valid,
    /* uint32_t keyDataLength           */ MCUXCLECC_WEIERECC_SECP192R1_SIZE_PRIVATEKEY));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != privkeyinit_token2) || (MCUXCLKEY_STATUS_OK != privkeyinit_result2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Validate key and expect MCUXCLKEY_STATUS_VALIDATION_PASSED */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyValidate_result2, keyValidate_token2, mcuxClKey_validate(
    /* mcuxClSession_Handle_t pSession   */ session,
    /* mcuxClKey_Validation_t validation */ mcuxClKey_Validation_WeierECC_PrivateKey,
    /* mcuxClKey_Handle_t key */            privKey));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_validate) != keyValidate_token2) || (MCUXCLKEY_STATUS_VALIDATION_PASSED != keyValidate_result2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Destroy Session and cleanup Session */
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
