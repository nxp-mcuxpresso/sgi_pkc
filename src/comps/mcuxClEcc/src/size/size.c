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

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClHashModes_Constants.h> // hash output sizes
#include <internal/mcuxClHashModes_Internal_Memory.h>
#include <internal/mcuxClRandomModes_Internal_SizeDefinitions.h>
#include <internal/mcuxClKey_Types_Internal.h>

#include <mcuxClEcc_Types.h>
#include <internal/mcuxClPkc_Internal_Types.h>
#include <internal/mcuxClEcc_Internal.h>

#include <internal/mcuxClSignature_Internal.h>

#include <internal/mcuxClEcc_ECDSA_Internal.h>

#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal_Hash.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClEcc_TwEd_Internal.h>

#include <internal/mcuxClEcc_Weier_Internal.h>

#include <internal/mcuxClEcc_Mont_Internal_PkcWaLayout.h>

#include <internal/mcuxClEcc_TwEd_Internal_PkcWaLayout.h>


#define SIZEOF_ECCCPUWA_T  (MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_CpuWa_t)) + sizeof(uint32_t)) /* Reserve 1 word for making UPTR table start from 64-bit aligned address */

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()

volatile uint8_t mcuxClEcc_GenerateKeyPair_WaCPU_SIZE     [SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_GENERATEKEYPAIR_NO_OF_BUFFERS + ECC_GENERATEKEYPAIR_NO_OF_VIRTUALS)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_GenerateSignature_WaCPU_SIZE   [SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_GENERATESIGNATURE_NO_OF_BUFFERS + ECC_GENERATESIGNATURE_NO_OF_VIRTUALS)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_VerifySignature_WaCPU_SIZE     [SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_VERIFYSIGNATURE_NO_OF_BUFFERS + ECC_VERIFYSIGNATURE_NO_OF_VIRTUALS)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_KeyAgreement_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_KEYAGREEMENT_NO_OF_BUFFERS + ECC_KEYAGREEMENT_NO_OF_VIRTUALS)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_GenerateDomainParams_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS + ECC_GENERATEDOMAINPARAMS_NO_OF_VIRTUALS))];
volatile uint8_t mcuxClEcc_WeierECC_DecodePoint_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_DECODEPOINT_NO_OF_BUFFERS + ECC_DECODEPOINT_NO_OF_VIRTUALS))];


volatile uint8_t mcuxClEcc_WeierECC_PrivateKeyValidation_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_WEIERECC_PRIVATEKEYVALIDATION_NO_OF_BUFFERS + ECC_WEIERECC_PRIVATEKEYVALIDATION_NO_OF_VIRTUALS))];
volatile uint8_t mcuxClEcc_WeierECC_PublicKeyValidation_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_WEIERECC_PUBLICKEYVALIDATION_NO_OF_BUFFERS + ECC_WEIERECC_PUBLICKEYVALIDATION_NO_OF_VIRTUALS))];

volatile uint8_t mcuxClEcc_PKC_wordsize[MCUXCLPKC_WORDSIZE];

volatile uint8_t mcuxClEcc_GenerateKeyPair_WaPKC_NoOfBuffers   [ECC_GENERATEKEYPAIR_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_GenerateSignature_WaPKC_NoOfBuffers   [ECC_GENERATESIGNATURE_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_VerifySignature_WaPKC_NoOfBuffers     [ECC_VERIFYSIGNATURE_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_KeyAgreement_WaPKC_NoOfBuffers[ECC_KEYAGREEMENT_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_WeierECC_GenerateDomainParams_WaPKC_NoOfBuffers[ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_WeierECC_DecodePoint_WaPKC_NoOfBuffers[ECC_DECODEPOINT_NO_OF_BUFFERS];

volatile uint8_t mcuxClEcc_WeierECC_CustomDomainParamsSize_Fixed   [MCUXCLECC_CUSTOMPARAMS_SIZE_FIXED];
volatile uint8_t mcuxClEcc_WeierECC_CustomDomainParamsSize_NoOfPLen[MCUXCLECC_CUSTOMPARAMS_SIZE_NO_OF_PLEN];
volatile uint8_t mcuxClEcc_WeierECC_CustomDomainParamsSize_NoOfNLen[MCUXCLECC_CUSTOMPARAMS_SIZE_NO_OF_NLEN];

volatile uint8_t mcuxClEcc_GenerateKeyPair_WaPKC_Size_128   [(ECC_GENERATEKEYPAIR_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_GenerateKeyPair_WaPKC_Size_256   [(ECC_GENERATEKEYPAIR_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_GenerateKeyPair_WaPKC_Size_384   [(ECC_GENERATEKEYPAIR_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_GenerateKeyPair_WaPKC_Size_512   [(ECC_GENERATEKEYPAIR_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_GenerateKeyPair_WaPKC_Size_640   [(ECC_GENERATEKEYPAIR_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(80) + MCUXCLPKC_WORDSIZE)];


volatile uint8_t mcuxClEcc_GenerateSignature_WaPKC_Size_128   [(ECC_GENERATESIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_GenerateSignature_WaPKC_Size_256   [(ECC_GENERATESIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_GenerateSignature_WaPKC_Size_384   [(ECC_GENERATESIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_GenerateSignature_WaPKC_Size_512   [(ECC_GENERATESIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_GenerateSignature_WaPKC_Size_640   [(ECC_GENERATESIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(80) + MCUXCLPKC_WORDSIZE)];

volatile uint8_t mcuxClEcc_VerifySignature_WaPKC_Size_128  [(ECC_VERIFYSIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_VerifySignature_WaPKC_Size_256  [(ECC_VERIFYSIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_VerifySignature_WaPKC_Size_384  [(ECC_VERIFYSIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_VerifySignature_WaPKC_Size_512  [(ECC_VERIFYSIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_VerifySignature_WaPKC_Size_640  [(ECC_VERIFYSIGNATURE_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(80) + MCUXCLPKC_WORDSIZE)];

/* ECDSA signature protocol descriptor size */
volatile uint8_t mcuxClEcc_ECDSA_SignatureProtocolDescriptor_SIZE[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_ECDSA_SignatureProtocolDescriptor_t))];

volatile uint8_t mcuxClKey_Agreement_ECDH_WaPKC_Size_128 [(ECC_KEYAGREEMENT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClKey_Agreement_ECDH_WaPKC_Size_256 [(ECC_KEYAGREEMENT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClKey_Agreement_ECDH_WaPKC_Size_384 [(ECC_KEYAGREEMENT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClKey_Agreement_ECDH_WaPKC_Size_512 [(ECC_KEYAGREEMENT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClKey_Agreement_ECDH_WaPKC_Size_640 [(ECC_KEYAGREEMENT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(80) + MCUXCLPKC_WORDSIZE)];

volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_128 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_256 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_384 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_512 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_640 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(80) + MCUXCLPKC_WORDSIZE)];

volatile uint8_t mcuxClEcc_WeierECC_DecodePoint_WaPKC_Size_128 [(ECC_DECODEPOINT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_DecodePoint_WaPKC_Size_256 [(ECC_DECODEPOINT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_DecodePoint_WaPKC_Size_384 [(ECC_DECODEPOINT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_DecodePoint_WaPKC_Size_512 [(ECC_DECODEPOINT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_DecodePoint_WaPKC_Size_640 [(ECC_DECODEPOINT_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(80) + MCUXCLPKC_WORDSIZE)];


volatile uint8_t mcuxClEcc_WeierECC_PrivateKeyValidation_WaPKC_Size_128 [(ECC_WEIERECC_PRIVATEKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_PrivateKeyValidation_WaPKC_Size_256 [(ECC_WEIERECC_PRIVATEKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_PrivateKeyValidation_WaPKC_Size_384 [(ECC_WEIERECC_PRIVATEKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_PrivateKeyValidation_WaPKC_Size_512 [(ECC_WEIERECC_PRIVATEKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_PrivateKeyValidation_WaPKC_Size_640 [(ECC_WEIERECC_PRIVATEKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(80) + MCUXCLPKC_WORDSIZE)];

volatile uint8_t mcuxClEcc_WeierECC_PublicKeyValidation_WaPKC_Size_128 [(ECC_WEIERECC_PUBLICKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_PublicKeyValidation_WaPKC_Size_256 [(ECC_WEIERECC_PUBLICKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_PublicKeyValidation_WaPKC_Size_384 [(ECC_WEIERECC_PUBLICKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_PublicKeyValidation_WaPKC_Size_512 [(ECC_WEIERECC_PUBLICKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_PublicKeyValidation_WaPKC_Size_640 [(ECC_WEIERECC_PUBLICKEYVALIDATION_NO_OF_BUFFERS) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(80) + MCUXCLPKC_WORDSIZE)];

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()


MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClEcc_MontDH_GenerateKeyPair_Curve25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_MontDH_KeyAgreement_Curve25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS))];
volatile uint8_t mcuxClEcc_MontDH_GenerateKeyPair_Curve25519_WaPKC_SIZE[ECC_MONTDH_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLECC_MONTDH_CURVE25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_MontDH_KeyAgreement_Curve25519_WaPKC_SIZE[ECC_MONTDH_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLECC_MONTDH_CURVE25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_MontDH_GenerateKeyPair_Curve448_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_MontDH_KeyAgreement_Curve448_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS))];
volatile uint8_t mcuxClEcc_MontDH_GenerateKeyPair_Curve448_WaPKC_SIZE[ECC_MONTDH_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLECC_MONTDH_CURVE448_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_MontDH_KeyAgreement_Curve448_WaPKC_SIZE[ECC_MONTDH_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLECC_MONTDH_CURVE448_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()



#define SIZEOF_EDDSA_UPTRT  MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE((sizeof(uint16_t)) * (ECC_EDDSA_NO_OF_VIRTUALS + ECC_EDDSA_NO_OF_BUFFERS))

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClEcc_EdDSA_GenerateKeyPair_Ed25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                   + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)
                                                                   + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEY)
                                                                   + MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512
                                                                   /* Memory needed for the TwEd_SecureFixScalarMult CPU workarea */
                                                                   + (sizeof(mcuxClEcc_TwEd_SecureFixScalarMult_CpuWa_t) + sizeof(uint32_t))];
volatile uint8_t mcuxClEcc_EdDSA_GenerateSignature_Ed25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                     /* Memory needed for message pre-hashing */
                                                                     + MCUXCLHASH_OUTPUT_SIZE_SHA_512
                                                                     /* Memory needed for storing a hash context for the upcoming multipart hash operations */
                                                                     + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_STATE_SIZE_SHA_512 + MCUXCLHASH_BLOCK_SIZE_SHA_512)
                                                                     + MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512
                                                                     /* Memory needed for storing a secure hash context for the upcoming multipart hash operations on secure data */
                                                                     + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_STATE_SIZE_SECSHA_512 + MCUXCLHASH_BLOCK_SIZE_SECSHA_512)
                                                                     + MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512
                                                                     /* Memory needed for the TwEd_SecureFixScalarMult CPU workarea */
                                                                     + (sizeof(mcuxClEcc_TwEd_SecureFixScalarMult_CpuWa_t) + sizeof(uint32_t))];
volatile uint8_t mcuxClEcc_EdDSA_VerifySignature_Ed25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                   /* Memory needed for message pre-hashing */
                                                                   + MCUXCLHASH_OUTPUT_SIZE_SHA_512
                                                                   /* Memory needed for storing a hash context for the upcoming multipart hash operations */
                                                                   + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_STATE_SIZE_SHA_512 + MCUXCLHASH_BLOCK_SIZE_SHA_512)
                                                                   + MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];

/* byteLenP = byteLenN in both Ed25519 and Ed448. */
volatile uint8_t mcuxClEcc_EdDSA_GenerateKeyPair_Ed25519_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLECC_EDDSA_ED25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_EdDSA_GenerateSignature_Ed25519_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLECC_EDDSA_ED25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_EdDSA_VerifySignature_Ed25519_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLECC_EDDSA_ED25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];


/* EdDSA key pair generation descriptor size */
volatile uint8_t mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_SIZE[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t) + sizeof(mcuxClKey_GenerationDescriptor_t))];

/* EdDSA signature mode generation descriptor size */
volatile uint8_t mcuxClEcc_EdDSA_SignatureProtocolDescriptor_SIZE[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t))];

/* EdDSA signature mode generation descriptor size */
volatile uint8_t mcuxClEcc_EdDSA_Signature_ProtocolMode_Descriptors_SIZE[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClSignature_ModeDescriptor_t) + sizeof(mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t))];

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

