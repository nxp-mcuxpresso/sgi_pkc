/*--------------------------------------------------------------------------*/
/* Copyright 2020-2026 NXP                                                  */
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
 * @example mcuxClRsa_Cipher_RSAES_PKCS1_v1_5_example.c
 * @brief mcuxClRsa example application
 */

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClRsa.h>
#include <mcuxClCipher.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

/**********************************************************/
/* Example test vectors                                   */
/**********************************************************/

#define RSA_KEY_BIT_LENGTH         (MCUXCLKEY_SIZE_2048)      ///< The example uses a 2048-bit key
#define RSA_KEY_BYTE_LENGTH        (RSA_KEY_BIT_LENGTH / 8U) ///< Converting the key-bitlength to bytelength
#define RSA_PUBLIC_EXP_BYTE_LENGTH (3U)                      ///< The public exponent has a length of three bytes
#define INPUT_MESSAGE_LENGTH       (64U)                     ///< Arbitrary size of the message to be encrypted/decrypted

/**
 * @brief Example value for public RSA modulus N.
 */
static const uint8_t modulus[RSA_KEY_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0xBEU, 0xD8U, 0xFFU, 0x2DU, 0xBCU, 0xE9U, 0x6EU, 0xCBU, 0x7CU, 0xB6U, 0x86U, 0x86U, 0x6DU, 0x01U, 0x98U, 0x41U,
  0x49U, 0x38U, 0x06U, 0xCAU, 0x50U, 0x8FU, 0x5CU, 0xF0U, 0x3AU, 0x02U, 0x90U, 0x90U, 0x5BU, 0xC5U, 0x1AU, 0xCCU,
  0xE6U, 0x69U, 0x17U, 0xF2U, 0x53U, 0x58U, 0xC0U, 0x94U, 0x93U, 0xEAU, 0x57U, 0x2BU, 0xC1U, 0x09U, 0x69U, 0x46U,
  0x81U, 0xD3U, 0x15U, 0x4CU, 0xD5U, 0x23U, 0xBEU, 0x32U, 0x06U, 0xB6U, 0xD0U, 0xEAU, 0x30U, 0xD3U, 0xDDU, 0x65U,
  0x9BU, 0xE8U, 0xACU, 0xC7U, 0x0BU, 0x4CU, 0xA5U, 0x14U, 0xE9U, 0x01U, 0x9EU, 0x4EU, 0xEEU, 0x2FU, 0x57U, 0x8AU,
  0x64U, 0x71U, 0x59U, 0xC9U, 0x4CU, 0x11U, 0xE2U, 0xE0U, 0xECU, 0xC9U, 0x96U, 0x75U, 0xF4U, 0x92U, 0xDFU, 0x1EU,
  0x84U, 0x78U, 0xBDU, 0xC4U, 0x3CU, 0xC1U, 0x03U, 0x8DU, 0x3CU, 0x4EU, 0x70U, 0x25U, 0x22U, 0x0AU, 0x15U, 0x0AU,
  0xFFU, 0x9EU, 0x2BU, 0x45U, 0x0CU, 0x72U, 0x11U, 0x0AU, 0xE5U, 0x4BU, 0x3CU, 0xCBU, 0x8AU, 0x80U, 0x3CU, 0x41U,
  0x42U, 0xFEU, 0x78U, 0x34U, 0xF0U, 0x1AU, 0x55U, 0x37U, 0x1BU, 0x7DU, 0x3AU, 0xEEU, 0x38U, 0x25U, 0x58U, 0x52U,
  0x27U, 0x75U, 0x9EU, 0x59U, 0x41U, 0xFAU, 0x43U, 0x11U, 0x92U, 0xB9U, 0x70U, 0x17U, 0x1DU, 0x4BU, 0x11U, 0xDAU,
  0xE0U, 0xF5U, 0xB7U, 0x77U, 0x48U, 0x93U, 0x4EU, 0x3BU, 0x68U, 0x60U, 0x08U, 0x86U, 0x57U, 0xD6U, 0x61U, 0xBFU,
  0x4AU, 0x31U, 0x41U, 0xFAU, 0x11U, 0xFBU, 0x3AU, 0x90U, 0x3AU, 0x22U, 0xB8U, 0xE0U, 0x38U, 0x27U, 0xB9U, 0x25U,
  0x8DU, 0x0EU, 0xDEU, 0x8AU, 0xDCU, 0x65U, 0x04U, 0x7BU, 0xDFU, 0x4AU, 0xA0U, 0x5FU, 0x78U, 0x8FU, 0x7EU, 0xC5U,
  0x66U, 0xFFU, 0x85U, 0x33U, 0x73U, 0x06U, 0x23U, 0x24U, 0x39U, 0x1FU, 0x66U, 0x26U, 0x18U, 0x16U, 0x53U, 0x30U,
  0x2EU, 0x24U, 0xC4U, 0x92U, 0x39U, 0x13U, 0x14U, 0x98U, 0x53U, 0x84U, 0xEAU, 0x99U, 0xDCU, 0x40U, 0x57U, 0x30U,
  0xC4U, 0x2FU, 0xE7U, 0x89U, 0xB6U, 0x69U, 0x5DU, 0x60U, 0x0FU, 0x4BU, 0x1DU, 0x66U, 0x54U, 0x22U, 0x8DU, 0xB1U
 };

/**
 * @brief Example value for prime factor P.
 */
static const uint8_t primeP[RSA_KEY_BYTE_LENGTH/2] __attribute__ ((aligned (4))) = {
  0xC1U, 0x26U, 0x5CU, 0x6BU, 0xD6U, 0x5CU, 0x5DU, 0x57U, 0xBFU, 0xA9U, 0x60U, 0x2EU, 0xCAU, 0x66U, 0x30U, 0x46U,
  0xD8U, 0x2AU, 0x16U, 0x1EU, 0xEAU, 0xB3U, 0xD7U, 0xF2U, 0x15U, 0xABU, 0x39U, 0xD4U, 0x9BU, 0xFCU, 0x4AU, 0xB3U,
  0x67U, 0x8AU, 0xC0U, 0x17U, 0xE7U, 0x43U, 0x6BU, 0x3DU, 0xF1U, 0xB3U, 0xA3U, 0x31U, 0x13U, 0x21U, 0x3BU, 0x98U,
  0x53U, 0x14U, 0x73U, 0x7DU, 0x10U, 0xEBU, 0x72U, 0x3EU, 0x2EU, 0x08U, 0xC8U, 0xC9U, 0x57U, 0xC7U, 0x45U, 0xDFU,
  0x5DU, 0xD5U, 0x6EU, 0xF4U, 0xABU, 0x99U, 0x66U, 0x8CU, 0x5FU, 0x48U, 0xF0U, 0xD4U, 0x95U, 0xF2U, 0xEBU, 0xCBU,
  0x73U, 0x7FU, 0x70U, 0x69U, 0x6EU, 0x81U, 0x5DU, 0x86U, 0xACU, 0xFBU, 0xBDU, 0x02U, 0x97U, 0x5BU, 0xD3U, 0xEBU,
  0x3AU, 0x4DU, 0xBCU, 0x51U, 0xF5U, 0xA9U, 0x9BU, 0xC0U, 0xB4U, 0xFCU, 0x6CU, 0xF9U, 0xE2U, 0xC6U, 0xCAU, 0x5AU,
  0x42U, 0x6BU, 0x82U, 0x10U, 0xD8U, 0x47U, 0x8CU, 0xFCU, 0x9EU, 0x4BU, 0x11U, 0x8AU, 0xF3U, 0xE1U, 0x4EU, 0x23U
};

/**
 * @brief Example value for prime factor Q.
 */
static const uint8_t primeQ[RSA_KEY_BYTE_LENGTH/2] __attribute__ ((aligned (4))) = {
  0xFCU, 0xF2U, 0xDBU, 0xEFU, 0x1AU, 0x9EU, 0x4EU, 0xD5U, 0x74U, 0x1DU, 0xF0U, 0x08U, 0x58U, 0xD4U, 0xEBU, 0xDEU,
  0x88U, 0x45U, 0xADU, 0xC0U, 0xD3U, 0xA6U, 0xA2U, 0x36U, 0x93U, 0xE7U, 0x3BU, 0x68U, 0x51U, 0x18U, 0x63U, 0x16U,
  0x79U, 0x8DU, 0x4FU, 0x08U, 0x2EU, 0xE1U, 0x7EU, 0xDCU, 0x6FU, 0x41U, 0x53U, 0x64U, 0xF1U, 0xE0U, 0x3AU, 0xDFU,
  0xD4U, 0x7DU, 0x98U, 0xF8U, 0x93U, 0x23U, 0xEEU, 0x52U, 0xC4U, 0x2EU, 0x31U, 0x50U, 0xFAU, 0x68U, 0x73U, 0xA0U,
  0x93U, 0xAFU, 0xCFU, 0xA4U, 0x21U, 0xAEU, 0x43U, 0x0AU, 0x3FU, 0x97U, 0xCAU, 0x58U, 0x61U, 0x60U, 0xB7U, 0xE5U,
  0x78U, 0x35U, 0xD8U, 0xACU, 0x6FU, 0x11U, 0xBEU, 0x96U, 0xEBU, 0xA9U, 0xA9U, 0x0CU, 0x5AU, 0xE4U, 0x63U, 0x48U,
  0xBDU, 0x00U, 0x26U, 0xEBU, 0xD7U, 0xDEU, 0x6AU, 0xBDU, 0x0BU, 0xB8U, 0xA3U, 0x8AU, 0x34U, 0x12U, 0x88U, 0xC9U,
  0x84U, 0x4DU, 0xD3U, 0xA9U, 0x0AU, 0x5EU, 0xEDU, 0xA9U, 0x2FU, 0x1EU, 0x2BU, 0x09U, 0x2DU, 0x10U, 0x70U, 0x1BU
};

/**
 * @brief Example value for exponent DP.
 */
static const uint8_t dp[RSA_KEY_BYTE_LENGTH/2] __attribute__ ((aligned (4))) = {
  0x82U, 0xABU, 0x62U, 0x21U, 0x2EU, 0x5FU, 0x44U, 0x62U, 0xE5U, 0xEEU, 0x3FU, 0x7CU, 0xC8U, 0x3FU, 0x03U, 0xF0U,
  0x19U, 0xB3U, 0xB7U, 0x4DU, 0x69U, 0x39U, 0x0CU, 0x21U, 0xE1U, 0xD8U, 0xFAU, 0x01U, 0xC5U, 0x19U, 0x94U, 0xABU,
  0xF4U, 0xA3U, 0xA0U, 0xBBU, 0x4BU, 0x20U, 0x88U, 0x3FU, 0xDAU, 0xF1U, 0xCDU, 0xB8U, 0x98U, 0x99U, 0x86U, 0x08U,
  0xD2U, 0x43U, 0xE6U, 0xB1U, 0xB8U, 0xADU, 0xA0U, 0x97U, 0x42U, 0x6BU, 0x7CU, 0xF3U, 0x01U, 0xE8U, 0x75U, 0x73U,
  0xDCU, 0xB6U, 0x55U, 0x1FU, 0x3FU, 0xACU, 0x42U, 0xFDU, 0x3AU, 0x45U, 0x4DU, 0x70U, 0x74U, 0x95U, 0x68U, 0x42U,
  0x36U, 0xBCU, 0x03U, 0x9FU, 0xC0U, 0x3BU, 0xD2U, 0xBBU, 0x16U, 0xF2U, 0x23U, 0xF7U, 0xC9U, 0xD0U, 0x3CU, 0xF9U,
  0x49U, 0x73U, 0x67U, 0xB1U, 0x07U, 0x02U, 0x9CU, 0xB5U, 0x6DU, 0x7BU, 0xCCU, 0x79U, 0xEDU, 0x9AU, 0xD1U, 0x30U,
  0xE8U, 0xF8U, 0x74U, 0x80U, 0xD2U, 0xE0U, 0xEDU, 0x17U, 0xC6U, 0x3BU, 0x40U, 0xFEU, 0x01U, 0x69U, 0xEEU, 0x83U
};

/**
 * @brief Example value for exponent DQ.
 */
static const uint8_t dq[RSA_KEY_BYTE_LENGTH/2] __attribute__ ((aligned (4))) = {
  0xB0U, 0xBEU, 0x7DU, 0xA1U, 0x10U, 0x07U, 0x67U, 0xECU, 0x4CU, 0x6BU, 0x92U, 0xCAU, 0x32U, 0x4FU, 0xECU, 0xD4U,
  0x1CU, 0x82U, 0x1BU, 0x8BU, 0xAEU, 0x18U, 0x34U, 0x26U, 0x50U, 0xA8U, 0x74U, 0xE1U, 0x4AU, 0x30U, 0xF1U, 0x23U,
  0xC6U, 0x21U, 0x50U, 0x04U, 0xD6U, 0xC5U, 0x27U, 0xA0U, 0x9DU, 0x78U, 0x96U, 0xEDU, 0xE4U, 0xF8U, 0x9AU, 0x0AU,
  0xC6U, 0x6EU, 0x50U, 0x51U, 0xF8U, 0x76U, 0x55U, 0xD3U, 0xADU, 0x52U, 0xDDU, 0x90U, 0xC8U, 0xB7U, 0xEDU, 0x7BU,
  0x59U, 0x56U, 0xB2U, 0x8EU, 0xECU, 0x1DU, 0xD8U, 0xA8U, 0x33U, 0x91U, 0x3BU, 0x89U, 0x0FU, 0xD9U, 0xC6U, 0x05U,
  0x68U, 0x3EU, 0xAFU, 0xBCU, 0xA5U, 0x0BU, 0x50U, 0x12U, 0x22U, 0x6EU, 0xF5U, 0x39U, 0x35U, 0xD5U, 0x79U, 0xEEU,
  0x5CU, 0x69U, 0xDBU, 0xC8U, 0x55U, 0x99U, 0x0BU, 0x1AU, 0x37U, 0x33U, 0x77U, 0xCAU, 0x5CU, 0xE2U, 0x4AU, 0x84U,
  0x0CU, 0x97U, 0x58U, 0xFBU, 0x37U, 0xCCU, 0xE6U, 0xE1U, 0x9DU, 0x93U, 0xC5U, 0xDCU, 0x6EU, 0x89U, 0x9AU, 0xDBU
};

/**
 * @brief Example value for qInv.
 */
static const uint8_t qInv[RSA_KEY_BYTE_LENGTH/2] __attribute__ ((aligned (4))) = {
  0x66U, 0xB2U, 0x11U, 0x6FU, 0x95U, 0xF8U, 0x21U, 0x42U, 0xC3U, 0xAEU, 0x71U, 0xBDU, 0x49U, 0x1DU, 0x2EU, 0xF9U,
  0x8DU, 0xE8U, 0xEFU, 0xBEU, 0x98U, 0xB3U, 0xD2U, 0x36U, 0xD5U, 0x34U, 0x48U, 0x2BU, 0xF8U, 0x3EU, 0xB1U, 0x85U,
  0xF4U, 0x87U, 0x3BU, 0x16U, 0xD3U, 0xEEU, 0x2CU, 0xCEU, 0xA9U, 0x05U, 0xDBU, 0x59U, 0x0FU, 0x73U, 0x5CU, 0x33U,
  0xEAU, 0x70U, 0xF7U, 0xF3U, 0xF6U, 0x88U, 0x7CU, 0xC1U, 0x1DU, 0x87U, 0xDDU, 0xA0U, 0x33U, 0x1CU, 0xAEU, 0x6DU,
  0x08U, 0xA4U, 0x5CU, 0x3FU, 0x41U, 0x5CU, 0x1CU, 0x18U, 0x7CU, 0xB8U, 0x45U, 0x53U, 0x57U, 0x9AU, 0x91U, 0x1FU,
  0x41U, 0xF9U, 0x1DU, 0x9AU, 0x9AU, 0x1EU, 0x1DU, 0xFCU, 0x75U, 0x36U, 0x42U, 0xE5U, 0x6BU, 0x21U, 0x9CU, 0x67U,
  0xF2U, 0x66U, 0xFBU, 0x62U, 0xC4U, 0xE9U, 0xF8U, 0x51U, 0x1DU, 0xD9U, 0xBDU, 0xB8U, 0x25U, 0xD8U, 0xE5U, 0x60U,
  0x9DU, 0x3CU, 0xA1U, 0xDEU, 0x05U, 0xDCU, 0x29U, 0x2CU, 0x4AU, 0x55U, 0xEDU, 0xF6U, 0xADU, 0xF2U, 0xC4U, 0xDFU
};

/**
 * @brief Example value for public RSA exponent e.
 */
static const uint8_t pubExp[RSA_PUBLIC_EXP_BYTE_LENGTH] __attribute__ ((aligned (4))) = {
  0x01U, 0x00U, 0x01U
};

/**
 * @brief Example plaintext to be encrypted.
 */
static const uint8_t plainData[INPUT_MESSAGE_LENGTH] = {
  0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U,
  0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U,
  0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
  0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U, 0x73U
};


MCUXCLEXAMPLE_FUNCTION(mcuxClRsa_Cipher_RSAES_PKCS1_v1_5_example)
{
  /**************************************************************************/
  /* Preparation: setup session                                             */
  /**************************************************************************/

  #define CPU_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLCORE_MAX(MCUXCLCORE_MAX(\
                                              MCUXCLRANDOM_NCINIT_WACPU_SIZE,\
                                              MCUXCLRANDOMMODES_INIT_WACPU_SIZE),\
                                              MCUXCLRSA_ENCRYPT_WACPU_SIZE(RSA_KEY_BIT_LENGTH)),\
                                              MCUXCLRSA_DECRYPT_WACPU_SIZE(RSA_KEY_BIT_LENGTH))
  #define PKC_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLRSA_ENCRYPT_WAPKC_SIZE(RSA_KEY_BIT_LENGTH),\
                                              MCUXCLRSA_DECRYPT_WAPKC_SIZE(RSA_KEY_BIT_LENGTH))


  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  //Allocate and initialize session
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                              CPU_WA_BUFFER_SIZE,
                                              PKC_WA_BUFFER_SIZE);

  /**************************************************************************/
  /* Initialize the RNG context and initialize the PRNG                     */
  /**************************************************************************/

#if defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_128)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES128_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES128_DRG3);
#else
  #error "Example not supported for target"
#endif /* MCUXCL_FEATURE_RANDOMMODES_* */

  /**************************************************************************/
  /* Preparation: setup RSA key                                             */
  /**************************************************************************/

  /* Allocation of key data buffers, which contain RSA key parameters */
  mcuxClRsa_KeyData_Crt_t privKeyStruct = {
                              .p.pKeyEntryData = (uint8_t*)primeP,
                              .p.keyEntryLength = sizeof(primeP),
                              .q.pKeyEntryData = (uint8_t*)primeQ,
                              .q.keyEntryLength = sizeof(primeQ),
                              .qInv.pKeyEntryData = (uint8_t*)qInv,
                              .qInv.keyEntryLength = sizeof(qInv),
                              .dp.pKeyEntryData = (uint8_t*)dp,
                              .dp.keyEntryLength = sizeof(dp),
                              .dq.pKeyEntryData = (uint8_t*)dq,
                              .dq.keyEntryLength = sizeof(dq),
                              .e.pKeyEntryData = (uint8_t*)pubExp,
                              .e.keyEntryLength = sizeof(pubExp)

  };

  mcuxClRsa_KeyData_Plain_t pubKeyStruct = {
                              .modulus.pKeyEntryData = (uint8_t*)modulus,
                              .modulus.keyEntryLength = RSA_KEY_BYTE_LENGTH,
                              .exponent.pKeyEntryData = (uint8_t*)pubExp,
                              .exponent.keyEntryLength = sizeof(pubExp)
  };

  /* Initialize RSA private key */
  uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_priv_status, ki_priv_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ privKey,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Rsa_PrivateCRT_DFA_2048,
    /* uint8_t * pKeyData                    */ (uint8_t *) &privKeyStruct,
    /* uint32_t keyDataLength                */ sizeof(privKeyStruct)
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_priv_token) || (MCUXCLKEY_STATUS_OK != ki_priv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Initialize RSA public key */
  uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_status, ki_pub_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session         */ session,
    /* mcuxClKey_Handle_t key                 */ pubKey,
    /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Rsa_Public_2048,
    /* uint8_t * pKeyData                    */ (uint8_t *) &pubKeyStruct,
    /* uint32_t keyDataLength                */ sizeof(pubKeyStruct)
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Preparation: setup RSAES_PKCS1_v1_5                                    */
  /**************************************************************************/

  /* Fill mode descriptor with the relevant data for the selected padding and hash algorithms */
  uint8_t cipherModeBytes[MCUXCLRSA_CIPHER_MODE_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClCipher_ModeDescriptor_t *pCipherMode = (mcuxClCipher_ModeDescriptor_t *) cipherModeBytes;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(construct_mode_token,
    mcuxClRsa_CipherModeConstructor_RSAES_PKCS1_v1_5(/* mcuxClCipher_ModeDescriptor_t * pCipherMode: */ pCipherMode)
  );

  if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_CipherModeConstructor_RSAES_PKCS1_v1_5) != construct_mode_token)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

  /**************************************************************************/
  /* Encryption                                                             */
  /**************************************************************************/

  uint8_t encryptedData[RSA_KEY_BYTE_LENGTH];
  uint32_t encryptedSize = 0U;

  MCUXCLBUFFER_INIT_RO(plainDataBuf, session, plainData, INPUT_MESSAGE_LENGTH);
  MCUXCLBUFFER_INIT(encryptedDataBuf, session, encryptedData, RSA_KEY_BYTE_LENGTH);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("Pointer is not dereferenced")
  const mcuxClCipher_Status_t e_status = mcuxClCipher_encrypt(
    /* mcuxClSession_Handle_t session          */ session,
    /* const mcuxClKey_Handle_t key            */ pubKey,
    /* mcuxClCipher_Mode_t mode                */ pCipherMode,
    /* mcuxCl_InputBuffer_t pIv                */ NULL, /* Unused for RSAES-PKCS1-v1_5 */
    /* uint32_t ivLength                      */ 0U,
    /* mcuxCl_InputBuffer_t pIn                */ plainDataBuf,
    /* uint32_t inLength                      */ sizeof(plainData),
    /* mcuxCl_Buffer_t pOut                    */ encryptedDataBuf,
    /* uint32_t * const pOutLength            */ &encryptedSize
  );
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  if(MCUXCLCIPHER_STATUS_OK != e_status)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if(encryptedSize != sizeof(encryptedData))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /**************************************************************************/
  /* Decryption                                                             */
  /**************************************************************************/

  uint32_t decryptedSize = 0U;
  uint8_t decryptedData[INPUT_MESSAGE_LENGTH];

  MCUXCLBUFFER_INIT(decryptedDataBuf, session, decryptedData, INPUT_MESSAGE_LENGTH);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("Pointer pIv is not dereferenced")
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("encryptedDataBuf initialized by MCUXCLBUFFER_INIT")
  const mcuxClCipher_Status_t d_status = mcuxClCipher_decrypt(
    /* mcuxClSession_Handle_t session         */ session,
    /* const mcuxClKey_Handle_t key           */ privKey,
    /* mcuxClCipher_Mode_t mode               */ pCipherMode,
    /* mcuxCl_InputBuffer_t pIv               */ NULL, /* Unused for RSAES-PKCS1-v1_5 */
    /* uint32_t ivLength                     */ 0U,
    /* mcuxCl_InputBuffer_t pIn               */ (mcuxCl_InputBuffer_t)encryptedDataBuf,
    /* uint32_t inLength                     */ encryptedSize,
    /* mcuxCl_Buffer_t pOut                   */ decryptedDataBuf,
    /* uint32_t * const pOutLength           */ &decryptedSize
  );
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  if(MCUXCLCIPHER_STATUS_OK != d_status)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if(decryptedSize != sizeof(decryptedData))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /**************************************************************************/
  /* Destroy the current session                                            */
  /**************************************************************************/

  if(!mcuxClExample_Session_Clean(session))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /**************************************************************************/
  /* Verification                                                           */
  /**************************************************************************/

  if(!mcuxClCore_assertEqual(plainData, decryptedData, sizeof(plainData)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}

