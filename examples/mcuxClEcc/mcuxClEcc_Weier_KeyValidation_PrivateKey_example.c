/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
