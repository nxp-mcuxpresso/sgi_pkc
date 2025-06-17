/*--------------------------------------------------------------------------*/
/* Copyright 2021-2024 NXP                                                  */
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

#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClRandomModes_MemoryConsumption.h>
#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <internal/mcuxClRandomModes_Private_NormalMode.h>
#include <internal/mcuxClRandomModes_Private_TestMode.h>
#include <internal/mcuxClRandomModes_Private_PrDisabled.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClRandomModes_DrbgAlgorithmsDescriptor_t mcuxClRandomModes_DrbgAlgorithmsDescriptor_CtrDrbg_PrDisabled =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    .instantiateAlgorithm = mcuxClRandomModes_CtrDrbg_instantiateAlgorithm,
    .reseedAlgorithm = mcuxClRandomModes_CtrDrbg_reseedAlgorithm,
    .generateAlgorithm = mcuxClRandomModes_CtrDrbg_generateAlgorithm,
    .selftestAlgorithm = mcuxClRandomModes_PrDisabled_selftestAlgorithm,
    .protectionTokenInstantiateAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_CtrDrbg_instantiateAlgorithm,
    .protectionTokenReseedAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_CtrDrbg_reseedAlgorithm,
    .protectionTokenGenerateAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_CtrDrbg_generateAlgorithm,
    .protectionTokenSelftestAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_PrDisabled_selftestAlgorithm
};

/* Constants for RNG health testing
 * This data does NOT originate from NIST DRBG test vectors (NIST SP 800-90A DRBGVS). It is provided by the RNG steering team. */
/* EntropyInput||Nonce = 1f4d063d959fd773aa0d0f446ef8f5ed02dd4c1d5166efe2974ff6a1c81bb50f2d282d3814b1fa5dfee09592244d5e2235063b24361857ab7c25f4ec48ede801 */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Init_Aes256_PrDisabled[] =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    0x3d064d1fu, 0x73d79f95u, 0x440f0daau, 0xedf5f86eu, 0x1d4cdd02u, 0xe2ef6651u, 0xa1f64f97u, 0x0fb51bc8u,
    0x382d282du, 0x5dfab114u, 0x9295e0feu, 0x225e4d24u, 0x243b0635u, 0xab571836u, 0xecf4257cu, 0x01e8ed48u
};

/* EntropyInputReseed = 685576d7db675fb95e23a646a935aa8e57ff1645cabdd851e3ee1f71d15cbe4af0d43973a5de33c5c873daf10bb4b4c8 */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes256_PrDisabled[] =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    0xd7765568u, 0xb95f67dbu, 0x46a6235eu, 0x8eaa35a9u, 0x4516ff57u, 0x51d8bdcau, 0x711feee3u, 0x4abe5cd1u,
    0x7339d4f0u, 0xc533dea5u, 0xf1da73c8u, 0xc8b4b40bu
};

/* ReturnedBits = e7a7e570c1f356561878fde178279f82e547de6388731b0ee479641e1153ccec2610d9576b76df106df94b434fd3424de080fe23395865fd3d7dfffc4cd2ccad */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_RandomData_Aes256_PrDisabled[] = {
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
    0x70e5a7e7u, 0x5656f3c1u, 0xe1fd7818u, 0x829f2778u, 0x63de47e5u, 0x0e1b7388u, 0x1e6479e4u, 0xeccc5311u,
    0x57d91026u, 0x10df766bu, 0x434bf96du, 0x4d42d34fu, 0x23fe80e0u, 0xfd655839u, 0xfcff7d3du, 0xadccd24cu
};

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t * const mcuxClRandomModes_TestVectors_Aes256_PrDisabled[MCUXCLRANDOMMODES_NO_OF_TESTVECTORS_PRDISABLED] =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    mcuxClRandomModes_TestVectors_Entropy_Init_Aes256_PrDisabled,
    mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes256_PrDisabled,
    mcuxClRandomModes_TestVectors_RandomData_Aes256_PrDisabled
};



MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const mcuxClRandomModes_DrbgModeDescriptor_t mcuxClRandomModes_DrbgModeDescriptor_CtrDrbg_AES256_PrDisabled =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    .pDrbgAlgorithms = &mcuxClRandomModes_DrbgAlgorithmsDescriptor_CtrDrbg_PrDisabled,
    .pDrbgVariant = &mcuxClRandomModes_DrbgVariantDescriptor_CtrDrbg_AES256,
    .pDrbgTestVectors = mcuxClRandomModes_TestVectors_Aes256_PrDisabled,
    .continuousReseedInterval = 0u
};




MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the generic structure member.")
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClRandom_ModeDescriptor_t mcuxClRandomModes_mdCtrDrbg_AES256_DRG3 = {
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
    .pOperationMode   = &mcuxClRandomModes_OperationModeDescriptor_NormalMode_PrDisabled,
    .pDrbgMode        = (void *) &mcuxClRandomModes_DrbgModeDescriptor_CtrDrbg_AES256_PrDisabled,
    .contextSize      = MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE,
    .auxParam         = (uint32_t *) &mcuxClRandomModes_OperationModeDescriptor_TestMode_PrDisabled,
    .securityStrength = MCUXCLRANDOMMODES_SECURITYSTRENGTH_CTR_DRBG_AES256
};
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()

