/*--------------------------------------------------------------------------*/
/* Copyright 2020-2024 NXP                                                  */
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
 * @file  mcuxClRsa_MemoryConsumption.h
 * @brief Defines the memory consumption for the mcuxClRsa component
 */

#ifndef MCUXCLRSA_MEMORYCONSUMPTION_H_
#define MCUXCLRSA_MEMORYCONSUMPTION_H_

#define MCUXCLRSA_SIGNATURE_PROTOCOLDESCRIPTOR_SIZE     (52u)

/**
 * @defgroup MCUXCLRSA_KEYGEN_MODE_SIZE MCUXCLRSA_KEYGEN_MODE_SIZE
 * @brief Definitions of RSA key generation mode descriptor sizes for the @ref mcuxClRsa_KeyGeneration_ModeConstructor function.
 * @ingroup mcuxClRsa_KeyGeneration_ModeDescriptor
 * @{
 */
#define MCUXCLRSA_KEYGEN_MODE_SIZE       (20u) ///< Definitions of RSA key generation mode descriptor size for the @ref mcuxClRsa_KeyGeneration_ModeConstructor function.
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa Sign                      */
/****************************************************************************/

/**
 * @defgroup MCUXCLRSA_SIGN_WA MCUXCLRSA_SIGN_WA
 * @brief Definitions of workarea sizes for the mcuxClRsa Sign
 * @ingroup mcuxClRsa_Macros
 * @{
 */


#define MCUXCLRSA_SIGN_PLAIN_PSSENCODE_1024_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function for 1024-bit private plain keys using PSS encoding.
#define MCUXCLRSA_SIGN_PLAIN_PSSENCODE_2048_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function for 2048-bit private plain keys using PSS encoding.
#define MCUXCLRSA_SIGN_PLAIN_PSSENCODE_3072_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function for 3072-bit private plain keys using PSS encoding.
#define MCUXCLRSA_SIGN_PLAIN_PSSENCODE_4096_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function for 4096-bit private plain keys using PSS encoding.
#define MCUXCLRSA_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_PSSENCODE_4096_WACPU_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_PSSENCODE_3072_WACPU_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_PSSENCODE_2048_WACPU_SIZE : \
                                 MCUXCLRSA_SIGN_PLAIN_PSSENCODE_1024_WACPU_SIZE)))  ///< Macro to extract CPU workarea size to be used with a non-standard key length, with a private plain key.

#define MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_1024_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function for 1024-bit private plain keys using PKCS#1v1.5 encoding.
#define MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_2048_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function for 2048-bit private plain keys using PKCS#1v1.5 encoding.
#define MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_3072_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function for 3072-bit private plain keys using PKCS#1v1.5 encoding.
#define MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_4096_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function for 4096-bit private plain keys using PKCS#1v1.5 encoding.
#define MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_4096_WACPU_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_3072_WACPU_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_2048_WACPU_SIZE : \
                                 MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_1024_WACPU_SIZE)))  ///< Macro to extract CPU workarea size to be used with a non-standard key length, with a private plain key.

#define MCUXCLRSA_SIGN_PLAIN_1024_WAPKC_SIZE     (1200u) ///< Definition of PKC workarea size for the RSA Sign function for 1024-bit private plain keys.
#define MCUXCLRSA_SIGN_PLAIN_2048_WAPKC_SIZE     (2224u) ///< Definition of PKC workarea size for the RSA Sign function for 2048-bit private plain keys.
#define MCUXCLRSA_SIGN_PLAIN_3072_WAPKC_SIZE     (3248u) ///< Definition of PKC workarea size for the RSA Sign function for 3072-bit private plain keys.
#define MCUXCLRSA_SIGN_PLAIN_4096_WAPKC_SIZE     (4272u) ///< Definition of PKC workarea size for the RSA Sign function for 4096-bit private plain keys.
#define MCUXCLRSA_SIGN_PLAIN_WAPKC_SIZE(keyBitLength) \
        ((3072u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_4096_WAPKC_SIZE : \
        ((2048u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_3072_WAPKC_SIZE : \
        ((1024u < (keyBitLength)) ? MCUXCLRSA_SIGN_PLAIN_2048_WAPKC_SIZE : \
                                    MCUXCLRSA_SIGN_PLAIN_1024_WAPKC_SIZE)))  ///< Macro to extract PKC workarea size to be used with a non-standard key length, with a private plain key.


#define MCUXCLRSA_SIGN_CRT_PSSENCODE_1024_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function using PSS encoding for 1024-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_PSSENCODE_2048_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function using PSS encoding for 2048-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_PSSENCODE_3072_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function using PSS encoding for 3072-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_PSSENCODE_4096_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function using PSS encoding for 4096-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_PSSENCODE_WACPU_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_PSSENCODE_4096_WACPU_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_PSSENCODE_3072_WACPU_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_PSSENCODE_2048_WACPU_SIZE : \
                                 MCUXCLRSA_SIGN_CRT_PSSENCODE_1024_WACPU_SIZE)))  ///< Macro to extract CPU workarea size to be used with a non-standard key length, with a private CRT key.

#define MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_1024_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function using PKCS#1v1.5 encoding, for 1024-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_2048_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function using PKCS#1v1.5 encoding, for 2048-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_3072_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function using PKCS#1v1.5 encoding, for 3072-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_4096_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Sign function using PKCS#1v1.5 encoding, for 4096-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_4096_WACPU_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_3072_WACPU_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_2048_WACPU_SIZE : \
                                 MCUXCLRSA_SIGN_CRT_PKCS1V15ENCODE_1024_WACPU_SIZE)))  ///< Macro to extract CPU workarea size to be used with a non-standard key length, with a private CRT key.

#define MCUXCLRSA_SIGN_CRT_1024_WAPKC_SIZE     (1000u) ///< Definition of PKC workarea size for the RSA Sign function for 1024-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_2048_WAPKC_SIZE     (1896u) ///< Definition of PKC workarea size for the RSA Sign function for 2048-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_3072_WAPKC_SIZE     (2792u) ///< Definition of PKC workarea size for the RSA Sign function for 3072-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_4096_WAPKC_SIZE     (3688u) ///< Definition of PKC workarea size for the RSA Sign function for 4096-bit private CRT keys.
#define MCUXCLRSA_SIGN_CRT_WAPKC_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_4096_WAPKC_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_3072_WAPKC_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_SIGN_CRT_2048_WAPKC_SIZE : \
                                MCUXCLRSA_SIGN_CRT_1024_WAPKC_SIZE)))  ///< Macro to extract PKC workarea size to be used with a non-standard key length, with a private CRT key.

/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa Verify                    */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_VERIFY_WA MCUXCLRSA_VERIFY_WA
 * @brief Definitions of workarea sizes for the mcuxClRsa Verify
 * @ingroup mcuxClRsa_Macros
 * @{
 */


#define MCUXCLRSA_VERIFY_PSSVERIFY_WACPU_SIZE         (152u) ///< Definition of CPU workarea size for the RSA Verify function using PSS encoding.
#define MCUXCLRSA_VERIFY_PKCS1V15VERIFY_WACPU_SIZE    (152u) ///< Definition of CPU workarea size for the RSA Verify function using PKCS#1v1.5 encoding.

#define MCUXCLRSA_VERIFY_1024_WAPKC_SIZE     (728u) ///< Definition of PKC workarea size for the RSA Verify function for 1024-bit keys.
#define MCUXCLRSA_VERIFY_2048_WAPKC_SIZE     (1368u) ///< Definition of PKC workarea size for the RSA Verify function for 2048-bit keys.
#define MCUXCLRSA_VERIFY_3072_WAPKC_SIZE     (2008u) ///< Definition of PKC workarea size for the RSA Verify function for 3072-bit keys.
#define MCUXCLRSA_VERIFY_4096_WAPKC_SIZE     (2648u) ///< Definition of PKC workarea size for the RSA Verify function for 4096-bit keys.
#define MCUXCLRSA_VERIFY_WAPKC_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_VERIFY_4096_WAPKC_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_VERIFY_3072_WAPKC_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_VERIFY_2048_WAPKC_SIZE : \
                                MCUXCLRSA_VERIFY_1024_WAPKC_SIZE)))  ///< Macro to extract PKC workarea size to be used with a non-standard key length.



/** @} */


/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa Key Generation            */
/****************************************************************************/

/**
 * @defgroup MCUXCLRSA_KEYGENERATION_CRT_WA MCUXCLRSA_KEYGENERATION_CRT_WA
 * @brief Definitions of workarea sizes for the mcuxClKey_generate_keypair function required to generate RSA key in CRT form.
 * @ingroup mcuxClRsa_Macros
 * @{
 */
#define MCUXCLRSA_KEYGENERATION_CRT_1024_WACPU_SIZE    (544u) ///< Definition of CPU workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 1024-bit RSA keys in CRT form
#define MCUXCLRSA_KEYGENERATION_CRT_2048_WACPU_SIZE    (672u) ///< Definition of CPU workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 2048-bit RSA keys in CRT form
#define MCUXCLRSA_KEYGENERATION_CRT_3072_WACPU_SIZE    (800u) ///< Definition of CPU workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 3072-bit RSA keys in CRT form
#define MCUXCLRSA_KEYGENERATION_CRT_4096_WACPU_SIZE    (928u) ///< Definition of CPU workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 4096-bit RSA keys in CRT form
#define MCUXCLRSA_KEYGENERATION_CRT_WACPU_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_CRT_4096_WACPU_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_CRT_3072_WACPU_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_CRT_2048_WACPU_SIZE : \
                                MCUXCLRSA_KEYGENERATION_CRT_1024_WACPU_SIZE)))  ///< Macro to extract CPU workarea size (in bytes) for the given key length.

#define MCUXCLRSA_KEYGENERATION_CRT_1024_WAPKC_SIZE    (1048u) ///< Definition of PKC workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 1024-bit RSA keys in CRT form
#define MCUXCLRSA_KEYGENERATION_CRT_2048_WAPKC_SIZE    (1896u) ///< Definition of PKC workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 2048-bit RSA keys in CRT form
#define MCUXCLRSA_KEYGENERATION_CRT_3072_WAPKC_SIZE    (2792u) ///< Definition of PKC workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 3072-bit RSA keys in CRT form
#define MCUXCLRSA_KEYGENERATION_CRT_4096_WAPKC_SIZE    (3688u) ///< Definition of PKC workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 4096-bit RSA keys in CRT form
#define MCUXCLRSA_KEYGENERATION_CRT_WAPKC_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_CRT_4096_WAPKC_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_CRT_3072_WAPKC_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_CRT_2048_WAPKC_SIZE : \
                                MCUXCLRSA_KEYGENERATION_CRT_1024_WAPKC_SIZE)))  ///< Macro to extract PKC workarea size (in bytes) for the given key length.

/** @} */

/**
 * @defgroup MCUXCLRSA_KEYGENERATION_PLAIN_WA MCUXCLRSA_KEYGENERATION_PLAIN_WA
 * @brief Definitions of workarea sizes for the mcuxClKey_generate_keypair function required to generate RSA key in plain form.
 * @ingroup mcuxClRsa_Macros
 * @{
 */
#define MCUXCLRSA_KEYGENERATION_PLAIN_1024_WACPU_SIZE    (512u) ///< Definition of CPU workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 1024-bit RSA keys in plain form
#define MCUXCLRSA_KEYGENERATION_PLAIN_2048_WACPU_SIZE    (640u) ///< Definition of CPU workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 2048-bit RSA keys in plain form
#define MCUXCLRSA_KEYGENERATION_PLAIN_3072_WACPU_SIZE    (768u) ///< Definition of CPU workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 3072-bit RSA keys in plain form
#define MCUXCLRSA_KEYGENERATION_PLAIN_4096_WACPU_SIZE    (896u) ///< Definition of CPU workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 4096-bit RSA keys in plain form
#define MCUXCLRSA_KEYGENERATION_PLAIN_WACPU_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_PLAIN_4096_WACPU_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_PLAIN_3072_WACPU_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_PLAIN_2048_WACPU_SIZE : \
                                MCUXCLRSA_KEYGENERATION_PLAIN_1024_WACPU_SIZE)))  ///< Macro to extract CPU workarea size for the given key length.

#define MCUXCLRSA_KEYGENERATION_PLAIN_1024_WAPKC_SIZE    (1200u) ///< Definition of PKC workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 1024-bit RSA keys in plain form
#define MCUXCLRSA_KEYGENERATION_PLAIN_2048_WAPKC_SIZE    (2224u) ///< Definition of PKC workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 2048-bit RSA keys in plain form
#define MCUXCLRSA_KEYGENERATION_PLAIN_3072_WAPKC_SIZE    (3248u) ///< Definition of PKC workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 3072-bit RSA keys in plain form
#define MCUXCLRSA_KEYGENERATION_PLAIN_4096_WAPKC_SIZE    (4272u) ///< Definition of PKC workarea size (in bytes) for the mcuxClKey_generate_keypair function required to generate 4096-bit RSA keys in plain form
#define MCUXCLRSA_KEYGENERATION_PLAIN_WAPKC_SIZE(keyBitLength) \
    ((3072u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_PLAIN_4096_WAPKC_SIZE : \
    ((2048u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_PLAIN_3072_WAPKC_SIZE : \
    ((1024u < (keyBitLength)) ? MCUXCLRSA_KEYGENERATION_PLAIN_2048_WAPKC_SIZE : \
                                MCUXCLRSA_KEYGENERATION_PLAIN_1024_WAPKC_SIZE)))  ///< Macro to extract PKC workarea size for the given key length.

/** @} */

/**
 * @defgroup MCUXCLRSA_KEYGENERATION_KEY_DATA_SIZE MCUXCLRSA_KEYGENERATION_KEY_DATA_SIZE
 * @brief Definitions of buffer sizes for generated RSA key data using mcuxClKey_generate_keypair function.
 * @ingroup mcuxClRsa_Macros
 * @{
 */
#define MCUXCLRSA_KEYGENERATION_PLAIN_KEY_DATA_1024_SIZE     (272u)  ///< Definition of buffer size (in bytes) for the RSA private plain key data for 1024-bit keys
#define MCUXCLRSA_KEYGENERATION_PLAIN_KEY_DATA_2048_SIZE     (528u)  ///< Definition of buffer size (in bytes) for the RSA private plain key data for 2048-bit keys
#define MCUXCLRSA_KEYGENERATION_PLAIN_KEY_DATA_3072_SIZE     (784u)  ///< Definition of buffer size (in bytes) for the RSA private plain key data for 3072-bit keys
#define MCUXCLRSA_KEYGENERATION_PLAIN_KEY_DATA_4096_SIZE     (1040u)  ///< Definition of buffer size (in bytes) for the RSA private plain key data for 4096-bit keys

#define MCUXCLRSA_KEYGENERATION_CRT_KEY_DATA_1024_SIZE       (368u)  ///< Definition of buffer size (in bytes) for the RSA private CRT key data for 1024-bit keys
#define MCUXCLRSA_KEYGENERATION_CRT_KEY_DATA_2048_SIZE       (688u)  ///< Definition of buffer size (in bytes) for the RSA private CRT key data for 2048-bit keys
#define MCUXCLRSA_KEYGENERATION_CRT_KEY_DATA_3072_SIZE       (1008u)  ///< Definition of buffer size (in bytes) for the RSA private CRT key data for 3072-bit keys
#define MCUXCLRSA_KEYGENERATION_CRT_KEY_DATA_4096_SIZE       (1328u)  ///< Definition of buffer size (in bytes) for the RSA private CRT key data for 4096-bit keys

#define MCUXCLRSA_KEYGENERATION_CRTDFA_KEY_DATA_1024_SIZE    (496u)  ///< Definition of buffer size (in bytes) for the RSA private CRT DFA key data for 1024-bit keys
#define MCUXCLRSA_KEYGENERATION_CRTDFA_KEY_DATA_2048_SIZE    (944u)  ///< Definition of buffer size (in bytes) for the RSA private CRT DFA key data for 2048-bit keys
#define MCUXCLRSA_KEYGENERATION_CRTDFA_KEY_DATA_3072_SIZE    (1392u)  ///< Definition of buffer size (in bytes) for the RSA private CRT DFA key data for 3072-bit keys
#define MCUXCLRSA_KEYGENERATION_CRTDFA_KEY_DATA_4096_SIZE    (1840u)  ///< Definition of buffer size (in bytes) for the RSA private CRT DFA key data for 4096-bit keys

#define MCUXCLRSA_KEYGENERATION_PUBLIC_KEY_DATA_SIZE(keyByteLen, expByteLen) \
                                                            (16u + (keyByteLen) + (expByteLen))  ///< Definition of buffer size (in bytes) for the RSA public key data for given key and public exponent size (in bytes)
#define MCUXCLRSA_KEYGENERATION_PUBLIC_KEY_DATA_1024_SIZE    (272u)  ///< Definition of buffer size (in bytes) for the RSA public key data for 1024-bit keys
#define MCUXCLRSA_KEYGENERATION_PUBLIC_KEY_DATA_2048_SIZE    (528u)  ///< Definition of buffer size (in bytes) for the RSA public key data for 2048-bit keys
#define MCUXCLRSA_KEYGENERATION_PUBLIC_KEY_DATA_3072_SIZE    (784u)  ///< Definition of buffer size (in bytes) for the RSA public key data for 3072-bit keys
#define MCUXCLRSA_KEYGENERATION_PUBLIC_KEY_DATA_4096_SIZE    (1040u)  ///< Definition of buffer size (in bytes) for the RSA public key data for 4096-bit keys

/** @} */


#endif /* MCUXCLRSA_MEMORYCONSUMPTION_H_ */
