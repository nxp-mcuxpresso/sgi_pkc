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
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WACPU_SIZE    408u  ///< CPU workarea size (in bytes) for #mcuxClKey_generate_keypair.

#define MCUXCLSIGNATURE_SIGN_ECDSA_WACPU_SIZE            408u  ///< CPU workarea size (in bytes) for #mcuxClSignature_sign.

#define MCUXCLSIGNATURE_VERIFY_ECDSA_WACPU_SIZE          416u  ///< CPU workarea size (in bytes) for #mcuxClSignature_verify.

#define MCUXCLKEY_AGREEMENT_ECDH_WACPU_SIZE               408u  ///< CPU workarea size (in bytes) for #mcuxClKey_agreement.

#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WACPU_SIZE  88u  ///< CPU workarea size (in bytes) for #mcuxClEcc_WeierECC_GenerateDomainParams.

#define MCUXCLECC_WEIERECC_DECODEPOINT_WACPU_SIZE  80u  ///< CPU workarea size (in bytes) for #mcuxClEcc_WeierECC_DecodePoint.



/**
 * @}
 */  /* MCUXCLECC_WACPU_ */

/**
 * @addtogroup MCUXCLECC_MONTDH_WACPU_
 * @brief Define the CPU workarea size required by mcuxClEcc MontDH APIs.
 * @{
 */

#define MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE25519_WACPU_SIZE    404u  ///< CPU workarea size (in bytes) for #mcuxClEcc_MontDH_GenerateKeyPair.
#define MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WACPU_SIZE     88u  ///< CPU workarea size (in bytes) for #mcuxClEcc_MontDH_KeyAgreement.

#define MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE448_WACPU_SIZE      404u  ///< CPU workarea size (in bytes) for #mcuxClEcc_MontDH_GenerateKeyPair.
#define MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WACPU_SIZE       88u  ///< CPU workarea size (in bytes) for #mcuxClEcc_MontDH_KeyAgreement.

/**
 * @}
 */  /* MCUXCLECC_MONTDH_WACPU_ */

 /**
 * @addtogroup MCUXCLECC_EDDSA_WACPU_
 * @brief Define the CPU workarea size required by mcuxClEcc EdDSA APIs.
 * @{
 */

#define MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WACPU_SIZE    1008u  ///< CPU workarea size (in bytes) for #mcuxClEcc_EdDSA_GenerateKeyPair for Ed25519.
#define MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WACPU_SIZE  1492u  ///< CPU workarea size (in bytes) for #mcuxClEcc_EdDSA_GenerateSignature for Ed25519.
#define MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WACPU_SIZE    552u  ///< CPU workarea size (in bytes) for #mcuxClEcc_EdDSA_VerifySignature for Ed25519.


/**
 * @}
 */  /* MCUXCLECC_EDDSA_WACPU_ */

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
    (24u * (MCUXCLCORE_ALIGN_TO_WORDSIZE(MCUXCLECC_PKC_WORDSIZE, MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE))

#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_128 (576u)
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_256 (960u)
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_384 (1344u)
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_512 (1728u)
#define MCUXCLKEY_GENERATEKEYPAIR_WEIERECC_WAPKC_SIZE_640 (2112u)

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ECDSA_GenerateSignature for arbitrary lengths of p and n.
 */
#define MCUXCLECC_SIGN_WAPKC_SIZE(pByteLen,nByteLen)  \
    (24u * (MCUXCLCORE_ALIGN_TO_WORDSIZE(MCUXCLECC_PKC_WORDSIZE, MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE))

#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_128 (576u )
#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_256 (960u )
#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_384 (1344u )
#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_512 (1728u )
#define MCUXCLSIGNATURE_SIGN_ECDSA_WAPKC_SIZE_640 (2112u )

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ECDSA_VerifySignature for arbitrary lengths of p and n.
 */

#define MCUXCLECC_VERIFY_WAPKC_SIZE(pByteLen,nByteLen)  \
    (28u * (MCUXCLCORE_ALIGN_TO_WORDSIZE(MCUXCLECC_PKC_WORDSIZE, MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE))

#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_128 (672u)
#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_256 (1120u)
#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_384 (1568u)
#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_512 (2016u)
#define MCUXCLSIGNATURE_VERIFY_ECDSA_WAPKC_SIZE_640 (2464u)

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_ECDH_KeyAgreement for arbitrary lengths of p and n.
 */
#define MCUXCLECC_POINTMULT_WAPKC_SIZE(pByteLen,nByteLen)  \
    (24u * (MCUXCLCORE_ALIGN_TO_WORDSIZE(MCUXCLECC_PKC_WORDSIZE, MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE))

#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_128 (576u )
#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_256 (960u )
#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_384 (1344u )
#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_512 (1728u )
#define MCUXCLKEY_AGREEMENT_ECDH_WAPKC_SIZE_640 (2112u )

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_WeierECC_GenerateDomainParams for arbitrary lengths of p and n.
 */
#define MCUXCLECC_WEIERECC_GENERATEDOMAINPARAMS_WAPKC_SIZE(pByteLen,nByteLen)  \
    (22u * (MCUXCLCORE_ALIGN_TO_WORDSIZE(MCUXCLECC_PKC_WORDSIZE, MCUXCLCORE_MAX(pByteLen,nByteLen)) + MCUXCLECC_PKC_WORDSIZE))

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



/**
 * @}
 */  /* MCUXCLECC_WAPKC_ */

/**
 * @addtogroup MCUXCLECC_MONTDH_WAPKC_
 * @brief Define the PKC workarea size required by mcuxClEcc_Mont APIs.
 * @{
 */

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_MontDH_KeyGeneration.
 */
#define MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE25519_WAPKC_SIZE  880u
#define MCUXCLECC_MONTDH_GENERATEKEYPAIR_CURVE448_WAPKC_SIZE  1408u

/**
 * PKC workarea size (in bytes) for #mcuxClEcc_MontDH_KeyAgreement.
 */
#define MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WAPKC_SIZE  880u
#define MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WAPKC_SIZE  1408u

/**
 * @}
 */  /* MCUXCLECC_MONTDH_WAPKC_ */

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

/**
 * @brief Define for the buffer size (in bytes) for optimized custom ECC Weierstrass domain parameters
 */
#define MCUXCLECC_CUSTOMWEIERECCDOMAINPARAMS_SIZE(byteLenP, byteLenN)  \
    MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(64u  \
                            + 8u * (byteLenP)  \
                            + 2u * (byteLenN) )

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




/**
 * @}
 */  /* mcuxClEcc_MemoryConsumption */

#endif /* MCUXCLECC_MEMORYCONSUMPTION_H_ */
