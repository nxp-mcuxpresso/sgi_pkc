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
 * @example mcuxClEcc_WeierECC_CustomEccWeierType_BN256_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClToolchain.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClKey.h>
#include <mcuxClEcc.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>

#define BN256_BYTE_LEN_P  (32u)
#define BN256_BYTE_LEN_N  (32u)

static const ALIGNED uint8_t BN_P256_P[BN256_BYTE_LEN_P] =
{
    /* p = 0xFFFFFFFFFFFCF0CD46E5F25EEE71A49F0CDC65FB12980A82D3292DDBAED33013 */
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 0xF0u, 0xCDu,
    0x46u, 0xE5u, 0xF2u, 0x5Eu, 0xEEu, 0x71u, 0xA4u, 0x9Fu,
    0x0Cu, 0xDCu, 0x65u, 0xFBu, 0x12u, 0x98u, 0x0Au, 0x82u,
    0xD3u, 0x29u, 0x2Du, 0xDBu, 0xAEu, 0xD3u, 0x30u, 0x13u};

static const ALIGNED uint8_t BN_P256_A[BN256_BYTE_LEN_P] =
{
    /* a = 0x0000000000000000000000000000000000000000000000000000000000000000 */
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
};

static const ALIGNED uint8_t BN_P256_B[BN256_BYTE_LEN_P] =
{
    /* b = 0x0000000000000000000000000000000000000000000000000000000000000003 */
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x03u
};

static const ALIGNED uint8_t BN_P256_G[2u * BN256_BYTE_LEN_P] =
{
    /* G = (x,y) with
     * x = 0x0000000000000000000000000000000000000000000000000000000000000001 */
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u,
    /* y = 0x0000000000000000000000000000000000000000000000000000000000000002 */
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u
};

static const ALIGNED uint8_t BN_P256_N[BN256_BYTE_LEN_N] =
{
    /* n = 0xFFFFFFFFFFFCF0CD46E5F25EEE71A49E0CDC65FB1299921AF62D536CD10B500D */
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 0xF0u, 0xCDu,
    0x46u, 0xE5u, 0xF2u, 0x5Eu, 0xEEu, 0x71u, 0xA4u, 0x9Eu,
    0x0Cu, 0xDCu, 0x65u, 0xFBu, 0x12u, 0x99u, 0x92u, 0x1Au,
    0xF6u, 0x2Du, 0x53u, 0x6Cu, 0xD1u, 0x0Bu, 0x50u, 0x0Du
};


#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLRANDOM_NCINIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, \
                       MCUXCLCORE_MAX(MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WACPU_SIZE, \
                                     MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WACPU_SIZE)))

#define MAX_PKCWA_SIZE MCUXCLCORE_MAX(MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WAPKC_SIZE_256, \
                                     MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_256)

/**
 * Performs an example key derivation using the mcuxClKey component.
 * @retval MCUXCLEXAMPLE_STATUS_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR The example code failed
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_WeierECC_CustomEccWeierType_BN256_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);


    /**************************************************************************/
    /* Create structure providing custom domain parameters (BN_P256), which   */
    /* will be converted to the optimized form accepted by mcuxClEcc APIs      */
    /**************************************************************************/

    MCUXCLBUFFER_INIT_RO(buffP, NULL, BN_P256_P, BN256_BYTE_LEN_P);
    MCUXCLBUFFER_INIT_RO(buffA, NULL, BN_P256_A, BN256_BYTE_LEN_P);
    MCUXCLBUFFER_INIT_RO(buffB, NULL, BN_P256_B, BN256_BYTE_LEN_P);
    MCUXCLBUFFER_INIT_RO(buffG, NULL, BN_P256_G, BN256_BYTE_LEN_P * 2u);
    MCUXCLBUFFER_INIT_RO(buffN, NULL, BN_P256_N, BN256_BYTE_LEN_N);

    mcuxClEcc_Weier_BasicDomainParams_t EccWeierBasicDomainParams;
    EccWeierBasicDomainParams.pP   = buffP;
    EccWeierBasicDomainParams.pLen = BN256_BYTE_LEN_P;
    EccWeierBasicDomainParams.pA   = buffA;
    EccWeierBasicDomainParams.pB   = buffB;
    EccWeierBasicDomainParams.pG   = buffG;
    EccWeierBasicDomainParams.pN   = buffN;
    EccWeierBasicDomainParams.nLen = BN256_BYTE_LEN_N;


    /**************************************************************************/
    /* Convert custom domain parameters (BN_P256) and store it in             */
    /* the optimized form accepted by mcuxClEcc APIs                           */
    /**************************************************************************/

    uint32_t eccWeierDomainParams[MCUXCLECC_CUSTOMWEIERECCDOMAINPARAMS_SIZE(BN256_BYTE_LEN_P, BN256_BYTE_LEN_N) / (sizeof(uint32_t))];
    mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams = (mcuxClEcc_Weier_DomainParams_t *) eccWeierDomainParams;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(genOptEccParams_status, genOptEccParams_token,
        mcuxClEcc_WeierECC_GenerateDomainParams(session,
                                               pEccWeierDomainParams,
                                               &EccWeierBasicDomainParams,
                                               MCUXCLECC_OPTION_GENERATEPRECPOINT_YES)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_GenerateDomainParams) != genOptEccParams_token) || (MCUXCLECC_STATUS_OK != genOptEccParams_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Generate custom private and public key types for BN_P256               */
    /**************************************************************************/

    uint32_t customPrivKeyTypeDescriptor[MCUXCLKEY_CUSTOMTYPEDESCRIPTOR_SIZE_IN_WORDS] = {0};
    mcuxClKey_CustomType_t customPrivKeyType = (mcuxClKey_CustomType_t) customPrivKeyTypeDescriptor;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(genPrivKeyType_status, genPrivKeyType_token, mcuxClEcc_WeierECC_GenerateCustomKeyType(
        /* mcuxClKey_CustomType_t customType     */ customPrivKeyType,
        /* mcuxClKey_AlgorithmId_t algoId        */ MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM | MCUXCLKEY_ALGO_ID_PRIVATE_KEY,
        /* mcuxClKey_Size_t size                 */ MCUXCLKEY_SIZE_256,
        /* void *pCustomParams                  */ (void *) pEccWeierDomainParams,
        /* mcuxClKey_Encoding_t plainEncoding    */ mcuxClEcc_Encoding_WeierECC_PrivateKey_Plain)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_GenerateCustomKeyType) != genPrivKeyType_token) || (MCUXCLECC_STATUS_OK != genPrivKeyType_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t customPubKeyTypeDescriptor[MCUXCLKEY_CUSTOMTYPEDESCRIPTOR_SIZE_IN_WORDS] = {0};
    mcuxClKey_CustomType_t customPubKeyType = (mcuxClKey_CustomType_t) customPubKeyTypeDescriptor;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(genPubKeyType_status, genPubKeyType_token, mcuxClEcc_WeierECC_GenerateCustomKeyType(
        /* mcuxClKey_CustomType_t customType     */ customPubKeyType,
        /* mcuxClKey_AlgorithmId_t algoId        */ MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM | MCUXCLKEY_ALGO_ID_PUBLIC_KEY,
        /* mcuxClKey_Size_t size                 */ MCUXCLKEY_SIZE_512,
        /* void *pCustomParams                  */ (void *) pEccWeierDomainParams,
        /* mcuxClKey_Encoding_t plainEncoding    */ mcuxClEcc_Encoding_WeierECC_PublicKey_Plain)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_GenerateCustomKeyType) != genPubKeyType_token) || (MCUXCLECC_STATUS_OK != genPubKeyType_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Allocate space for and initialize private key handle for an BN_P256 private key */
    uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    ALIGNED uint8_t pPrivKeyData[MCUXCLKEY_SIZE_256];

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_priv_status, ki_priv_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ privKey,
    /* mcuxClKey_Type_t type                  */ customPrivKeyType,
    /* const uint8_t * pKeyData              */ pPrivKeyData,
    /* uint32_t keyDataLength                */ MCUXCLKEY_SIZE_256)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_priv_token) || (MCUXCLKEY_STATUS_OK != ki_priv_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Allocate space for and initialize public key handle for an BN_P256 public key */
    uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    ALIGNED uint8_t pPubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY];

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_status, ki_pub_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ pubKey,
    /* mcuxClKey_Type_t type                  */ customPubKeyType,
    /* const uint8_t * pKeyData              */ pPubKeyData,
    /* uint32_t keyDataLength                */ MCUXCLKEY_SIZE_512)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Initialize the RNG context and Initialize the PRNG */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);

    /**************************************************************************/
    /* Key pair generation for ECDSA on BN_P256                               */
    /**************************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(gkp_status, gkp_token, mcuxClKey_generate_keypair(
        /* mcuxClSession_Handle_t session:    */ session,
        /* mcuxClKey_Generation_t generation: */ mcuxClKey_Generation_ECDSA,
        /* mcuxClKey_Handle_t privKey:        */ privKey,
        /* mcuxClKey_Handle_t pubKey:         */ pubKey)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_generate_keypair) != gkp_token) || (MCUXCLKEY_STATUS_OK != gkp_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Clean session                                                          */
    /**************************************************************************/

    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
