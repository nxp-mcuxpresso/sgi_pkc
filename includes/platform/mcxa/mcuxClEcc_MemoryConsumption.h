/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/**
 * @file  mcuxClEcc_MemoryConsumption.h
 * @brief Defines the memory consumption for the mcuxClEcc component
 */

#ifndef MCUXCLECC_MEMORYCONSUMPTION_H_
#define MCUXCLECC_MEMORYCONSUMPTION_H_

#include <mcuxClCore_Macros.h>

/**
 * @defgroup mcuxClEcc_MemoryConsumption mcuxClEcc_MemoryConsumption
 * @brief Defines the memory consumption for the @ref mcuxClEcc component
 * @ingroup mcuxClEcc
 * @{
 */

/**
 * @addtogroup MCUXCLECC_WACPU_
 * @brief Define the CPU workarea size required by mcuxClEcc APIs.
 * @{
 */
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WACPU_SIZE    472u  ///< CPU workarea size (in bytes) for #mcuxClKey_generate_keypair.


#define MCUXCLSIGNATURE_SIGN_ECDSA_WACPU_SIZE            472u  ///< CPU workarea size (in bytes) for #mcuxClSignature_sign.

#define MCUXCLSIGNATURE_VERIFY_ECDSA_WACPU_SIZE          480u  ///< CPU workarea size (in bytes) for #mcuxClSignature_verify.

#define MCUXCLKEY_AGREEMENT_ECDH_WACPU_SIZE               472u  ///< CPU workarea size (in bytes) for #mcuxClKey_agreement.

#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WACPU_SIZE  156u  ///< CPU workarea size (in bytes) for #mcuxClEcc_WeierECC_GenerateDomainParams.

#define MCUXCLECC_WEIERECC_DECODEPOINT_WACPU_SIZE  148u  ///< CPU workarea size (in bytes) for #mcuxClEcc_WeierECC_DecodePoint.

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION
#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_SCALARMULT
#define MCUXCLECC_ARITHMETICOPERATION_SCALARMULT_WACPU_SIZE  $(mcuxClEcc_ArithmeticOperation_ScalarMult_WaCPU_SIZE)u  ///< CPU workarea size (in bytes) for #mcuxClEcc_ArithmeticOperation scalarMult.
#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_SCALARMULT */

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_SECURESCALARMULT
#define MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WACPU_SIZE  $(mcuxClEcc_ArithmeticOperation_SecureScalarMult_WaCPU_SIZE)u  ///< CPU workarea size (in bytes) for #mcuxClEcc_ArithmeticOperation scalarMult.
#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_SECURESCALARMULT */

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_POINTADD
#define MCUXCLECC_ARITHMETICOPERATION_POINTADD_WACPU_SIZE  $(mcuxClEcc_ArithmeticOperation_PointAdd_WaCPU_SIZE)u  ///< CPU workarea size (in bytes) for #mcuxClEcc_ArithmeticOperation point addition.
#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_POINTADD */

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_POINTSUB
#define MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WACPU_SIZE  $(mcuxClEcc_ArithmeticOperation_PointSub_WaCPU_SIZE)u  ///< CPU workarea size (in bytes) for #mcuxClEcc_ArithmeticOperation point subtraction.
#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_POINTSUB */
#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION */

#define MCUXCLECC_WEIERECC_PRIVATEKEYVALIDATION_WACPU_SIZE  132u  ///< CPU workarea size (in bytes) for #mcuxClEcc_WeierECC_PrivateKeyValidation.
#define MCUXCLECC_WEIERECC_PUBLICKEYVALIDATION_WACPU_SIZE  140u  ///< CPU workarea size (in bytes) for #mcuxClEcc_WeierECC_PublicKeyValidation.

/**
 * @}
 */  /* MCUXCLECC_WACPU_ */

#ifdef MCUXCL_FEATURE_ECC_MONTDH
/**
 * @addtogroup MCUXCLECC_MONTDH_WACPU_
 * @brief Define the CPU workarea size required by mcuxClEcc MontDH APIs.
 * @{
 */

#ifdef MCUXCL_FEATURE_ECC_CURVE25519
#define MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE25519_WACPU_SIZE    472u  ///< CPU workarea size (in bytes) for #mcuxClEcc_MontDH_GenerateKeyPair.
#define MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WACPU_SIZE     156u  ///< CPU workarea size (in bytes) for #mcuxClEcc_MontDH_KeyAgreement.
#endif /* MCUXCL_FEATURE_ECC_CURVE25519 */

#ifdef MCUXCL_FEATURE_ECC_CURVE448
#define MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE448_WACPU_SIZE      472u  ///< CPU workarea size (in bytes) for #mcuxClEcc_MontDH_GenerateKeyPair.
#define MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WACPU_SIZE       156u  ///< CPU workarea size (in bytes) for #mcuxClEcc_MontDH_KeyAgreement.
#endif /* MCUXCL_FEATURE_ECC_CURVE448 */

/**
 * @}
 */  /* MCUXCLECC_MONTDH_WACPU_ */
#endif /* MCUXCL_FEATURE_ECC_MONTDH */

#ifdef MCUXCL_FEATURE_ECC_EDDSA
 /**
 * @addtogroup MCUXCLECC_EDDSA_WACPU_
 * @brief Define the CPU workarea size required by mcuxClEcc EdDSA APIs.
 * @{
 */

#define MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WACPU_SIZE    1076u  ///< CPU workarea size (in bytes) for #mcuxClEcc_EdDSA_GenerateKeyPair for Ed25519.
#define MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WACPU_SIZE  1560u  ///< CPU workarea size (in bytes) for #mcuxClEcc_EdDSA_GenerateSignature for Ed25519.
#define MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WACPU_SIZE    620u  ///< CPU workarea size (in bytes) for #mcuxClEcc_EdDSA_VerifySignature for Ed25519.


/**
 * @}
 */  /* MCUXCLECC_EDDSA_WACPU_ */
#endif /* MCUXCL_FEATURE_ECC_EDDSA */

/**
 * @addtogroup MCUXCLECC_WAPKC_
 * @brief Define the PKC workarea size required by mcuxClEcc APIs.
 * @{
 */

/**
 * @brief PKC wordsize in ECC component.
 */
#define MCUXCLECC_PKC_WORDSIZE  8u

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_WeierECC_GenerateKeyPair for arbitrary lengths of p and n.
 */
#define MCUXCLECC_KEYGEN_WAPKC_SIZE(pByteLen,nByteLen)  \
    (1u + \
    (24u * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE)))

#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_128 (576u)
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_256 (960u)
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_384 (1344u)
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_512 (1728u)
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_640 (2112u)


/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ECDSA_GenerateSignature for arbitrary lengths of p and n.
 */
#define MCUXCLECC_SIGN_WAPKC_SIZE(pByteLen,nByteLen)  \
    (1u + \
    (24u * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE)))

#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_128 (576u )
#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_256 (960u )
#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_384 (1344u )
#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_512 (1728u )
#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_640 (2112u )

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ECDSA_VerifySignature for arbitrary lengths of p and n.
 */

#define MCUXCLECC_VERIFY_WAPKC_SIZE(pByteLen,nByteLen)  \
    (1u + \
    (28u * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE)))

#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_128 (672u)
#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_256 (1120u)
#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_384 (1568u)
#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_512 (2016u)
#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_640 (2464u)

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ECDH_KeyAgreement for arbitrary lengths of p and n.
 */
#define MCUXCLECC_POINTMULT_WAPKC_SIZE(pByteLen,nByteLen)  \
    (1u + \
    (24u * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE)))

#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_128 (576u )
#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_256 (960u )
#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_384 (1344u )
#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_512 (1728u )
#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_640 (2112u )

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_WeierECC_GenerateDomainParams for arbitrary lengths of p and n.
 */
#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WAPKC_SIZE(pByteLen,nByteLen)  \
    (1u + \
    (22u * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE)))

#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WAPKC_SIZE_128 (528u )
#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WAPKC_SIZE_256 (880u )
#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WAPKC_SIZE_384 (1232u )
#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WAPKC_SIZE_512 (1584u )
#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WAPKC_SIZE_640 (1936u )

/**
 * PKC workarea sizes (in bytes) for #mcuxClEcc_WeierECC_DecodePoint for supported lengths of p and n.
 */
#define MCUXCLECC_WEIERECC_DECODEPOINT_WAPKC_SIZE_128  (432u)
#define MCUXCLECC_WEIERECC_DECODEPOINT_WAPKC_SIZE_256  (720u)
#define MCUXCLECC_WEIERECC_DECODEPOINT_WAPKC_SIZE_384  (1008u)
#define MCUXCLECC_WEIERECC_DECODEPOINT_WAPKC_SIZE_512  (1296u)
#define MCUXCLECC_WEIERECC_DECODEPOINT_WAPKC_SIZE_640  (1584u)

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION
#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_SCALARMULT
/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ArithmeticOperation point multiplication for standard key sizes.
 */
#define MCUXCLECC_ARITHMETICOPERATION_SCALARMULT_WAPKC_SIZE_128  $(mcuxClEcc_ArithmeticOperation_ScalarMult_WaPKC_Size_128)u
#define MCUXCLECC_ARITHMETICOPERATION_SCALARMULT_WAPKC_SIZE_256  $(mcuxClEcc_ArithmeticOperation_ScalarMult_WaPKC_Size_256)u
#define MCUXCLECC_ARITHMETICOPERATION_SCALARMULT_WAPKC_SIZE_384  $(mcuxClEcc_ArithmeticOperation_ScalarMult_WaPKC_Size_384)u
#define MCUXCLECC_ARITHMETICOPERATION_SCALARMULT_WAPKC_SIZE_512  $(mcuxClEcc_ArithmeticOperation_ScalarMult_WaPKC_Size_512)u
#define MCUXCLECC_ARITHMETICOPERATION_SCALARMULT_WAPKC_SIZE_640  $(mcuxClEcc_ArithmeticOperation_ScalarMult_WaPKC_Size_640)u
#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_SCALARMULT */

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_SECURESCALARMULT
/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ArithmeticOperation secure point multiplication for standard key sizes.
 */
#define MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WAPKC_SIZE_128  $(mcuxClEcc_ArithmeticOperation_SecureScalarMult_WaPKC_Size_128)u
#define MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WAPKC_SIZE_256  $(mcuxClEcc_ArithmeticOperation_SecureScalarMult_WaPKC_Size_256)u
#define MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WAPKC_SIZE_384  $(mcuxClEcc_ArithmeticOperation_SecureScalarMult_WaPKC_Size_384)u
#define MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WAPKC_SIZE_512  $(mcuxClEcc_ArithmeticOperation_SecureScalarMult_WaPKC_Size_512)u
#define MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WAPKC_SIZE_640  $(mcuxClEcc_ArithmeticOperation_SecureScalarMult_WaPKC_Size_640)u
#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_SECURESCALARMULT */

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_POINTADD
/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ArithmeticOperation point addition for standard key sizes.
 */
#define MCUXCLECC_ARITHMETICOPERATION_POINTADD_WAPKC_SIZE_128  ($(mcuxClEcc_ArithmeticOperation_PointAdd_WaPKC_Size_128)u)
#define MCUXCLECC_ARITHMETICOPERATION_POINTADD_WAPKC_SIZE_256  ($(mcuxClEcc_ArithmeticOperation_PointAdd_WaPKC_Size_256)u)
#define MCUXCLECC_ARITHMETICOPERATION_POINTADD_WAPKC_SIZE_384  ($(mcuxClEcc_ArithmeticOperation_PointAdd_WaPKC_Size_384)u)
#define MCUXCLECC_ARITHMETICOPERATION_POINTADD_WAPKC_SIZE_512  ($(mcuxClEcc_ArithmeticOperation_PointAdd_WaPKC_Size_512)u)
#define MCUXCLECC_ARITHMETICOPERATION_POINTADD_WAPKC_SIZE_640  ($(mcuxClEcc_ArithmeticOperation_PointAdd_WaPKC_Size_640)u)

#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_POINTADD */

#ifdef MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_POINTSUB
/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ArithmeticOperation point subtraction for standard key sizes.
 */
#define MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WAPKC_SIZE_128  ($(mcuxClEcc_ArithmeticOperation_PointSub_WaPKC_Size_128)u)
#define MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WAPKC_SIZE_256  ($(mcuxClEcc_ArithmeticOperation_PointSub_WaPKC_Size_256)u)
#define MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WAPKC_SIZE_384  ($(mcuxClEcc_ArithmeticOperation_PointSub_WaPKC_Size_384)u)
#define MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WAPKC_SIZE_512  ($(mcuxClEcc_ArithmeticOperation_PointSub_WaPKC_Size_512)u)
#define MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WAPKC_SIZE_640  ($(mcuxClEcc_ArithmeticOperation_PointSub_WaPKC_Size_640)u)

#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION_POINTSUB */
#endif /* MCUXCL_FEATURE_ECC_ARITHMETICOPERATION */

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_WeierECC_PrivateKeyValidation for standard key sizes.
 */
#define MCUXCLECC_WEIERECC_PRIVATEKEYVALIDATION_WAPKC_SIZE_128  (240u)
#define MCUXCLECC_WEIERECC_PRIVATEKEYVALIDATION_WAPKC_SIZE_256  (400u)
#define MCUXCLECC_WEIERECC_PRIVATEKEYVALIDATION_WAPKC_SIZE_384  (560u)
#define MCUXCLECC_WEIERECC_PRIVATEKEYVALIDATION_WAPKC_SIZE_512  (720u)
#define MCUXCLECC_WEIERECC_PRIVATEKEYVALIDATION_WAPKC_SIZE_640  (880u)

#define MCUXCLECC_WEIERECC_PUBLICKEYVALIDATION_WAPKC_SIZE_128  (336u)
#define MCUXCLECC_WEIERECC_PUBLICKEYVALIDATION_WAPKC_SIZE_256  (560u)
#define MCUXCLECC_WEIERECC_PUBLICKEYVALIDATION_WAPKC_SIZE_384  (784u)
#define MCUXCLECC_WEIERECC_PUBLICKEYVALIDATION_WAPKC_SIZE_512  (1008u)
#define MCUXCLECC_WEIERECC_PUBLICKEYVALIDATION_WAPKC_SIZE_640  (1232u)

/**
 * @}
 */  /* MCUXCLECC_WAPKC_ */

#if defined(MCUXCL_FEATURE_ECC_MONTDH)
/**
 * @addtogroup MCUXCLECC_MONTDH_WAPKC_
 * @brief Define the PKC workarea size required by mcuxClEcc_Mont APIs.
 * @{
 */

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_MontDH_KeyGeneration.
 */
#ifdef MCUXCL_FEATURE_ECC_CURVE25519
#define MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE25519_WAPKC_SIZE  880u
#endif /* MCUXCL_FEATURE_ECC_CURVE25519 */
#ifdef MCUXCL_FEATURE_ECC_CURVE448
#define MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE448_WAPKC_SIZE  1408u
#endif /* MCUXCL_FEATURE_ECC_CURVE448 */

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_MontDH_KeyAgreement.
 */
#ifdef MCUXCL_FEATURE_ECC_CURVE25519
#define MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WAPKC_SIZE  880u
#endif /* MCUXCL_FEATURE_ECC_CURVE25519 */
#ifdef MCUXCL_FEATURE_ECC_CURVE448
#define MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WAPKC_SIZE  1408u
#endif /* MCUXCL_FEATURE_ECC_CURVE448 */

/**
 * @}
 */  /* MCUXCLECC_MONTDH_WAPKC_ */
#endif /* defined(MCUXCL_FEATURE_ECC_MONTDH) && defined(MCUXCL_FEATURE_PKC) */

#if defined(MCUXCL_FEATURE_ECC_EDDSA)
/**
 * @addtogroup MCUXCLECC_EDDSA_WAPKC_
 * @brief Define the PKC workarea size required by mcuxClEcc EdDSA APIs.
 * @{
 */

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_EdDSA_GenerateKeyPair.
 */
#define MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WAPKC_SIZE    1800u  ///< PKC workarea size (in bytes) for #mcuxClEcc_EdDSA_GenerateKeyPair for Ed25519.

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_EdDSA_GenerateSignature.
 */
#define MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WAPKC_SIZE  1800u  ///< PKC workarea size (in bytes) for #mcuxClEcc_EdDSA_GenerateSignature for Ed25519.

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_EdDSA_VerifySignature.
 */
#define MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WAPKC_SIZE    1800u  ///< PKC workarea size (in bytes) for #mcuxClEcc_EdDSA_VerifySignature for Ed25519.

/**
 * @}
 */  /* MCUXCLECC_EDDSA_WAPKC_ */
#endif /*  defined(MCUXCL_FEATURE_ECC_EDDSA) && defined(MCUXCL_FEATURE_PKC) */

/**
 * @brief Define for the buffer size (in bytes) for optimized custom ECC Weierstrass domain parameters
 */
#define MCUXCLECC_CUSTOMWEIERECCDOMAINPARAMS_SIZE(byteLenP, byteLenN)  \
    MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(64u  \
                            + 8u * (byteLenP)  \
                            + 2u * (byteLenN) )

#ifdef MCUXCL_FEATURE_ECC_EDDSA
/**
 * @addtogroup MCUXCLECC_EDDSA_GENKEYPAIR_DESC_SIZE_
 * @brief Define for the EdDSA key pair generation descriptor size.
 * @{
 */
#define MCUXCLECC_EDDSA_GENERATEKEYPAIR_DESCRIPTOR_SIZE    20u  ///< EdDSA key pair generation descriptor size.
/**
 * @}
 */  /* MCUXCLECC_EDDSA_GENKEYPAIR_DESC_SIZE_ */

/**
 * @addtogroup MCUXCLECC_EDDSA_SIGNATURE_PROTOCOL_DESC_SIZE_
 * @brief Define for the EdDSA signature protocol descriptor size.
 * @{
 */
#define MCUXCLECC_EDDSA_SIGNATURE_PROTOCOL_DESCRIPTOR_SIZE 20u  ///< EdDSA signature generation descriptor size.

#define MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE_PROTOCOL_DESCRIPTOR(contextLen) \
    (MCUXCLECC_EDDSA_SIGNATURE_PROTOCOL_DESCRIPTOR_SIZE + MCUXCLECC_EDDSA_SIZE_HASH_PREFIX(MCUXCLECC_EDDSA_ED25519_DOMPREFIXLEN, (contextLen)))  ///< Byte length of an Ed25519 signature protocol descriptor.


/**
 * @}
 */  /* MCUXCLECC_EDDSA_SIGNATURE_PROTOCOL_DESC_SIZE_ */

/**
 * @addtogroup MCUXCLECC_EDDSA_SIGNATURE_MODE_SIZE_
 * @brief Define for the EdDSA signature protocol descriptor size.
 * @{
 */
#define MCUXCLECC_EDDSA_SIGNATURE_MODE_SIZE (40u)

#define MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE_MODE_DESCRIPTOR(contextLen) \
    (MCUXCLECC_EDDSA_SIGNATURE_MODE_SIZE + MCUXCLECC_EDDSA_SIZE_HASH_PREFIX(MCUXCLECC_EDDSA_ED25519_DOMPREFIXLEN, (contextLen)))                  ///< Byte length of an Ed25519 signature mode descriptor.



/**
 * @}
 */  /* MCUXCLECC_EDDSA_SIGNATURE_MODE_SIZE_ */

#endif /* MCUXCL_FEATURE_ECC_EDDSA */



/**
 * @}
 */  /* mcuxClEcc_MemoryConsumption */

#endif /* MCUXCLECC_MEMORYCONSUMPTION_H_ */
