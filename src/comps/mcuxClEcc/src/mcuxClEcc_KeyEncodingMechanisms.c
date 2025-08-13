/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @file  mcuxClEcc_KeyEncodingMechanisms.c
 * @brief mcuxClEcc: implementation of ECC key encoding mechanisms (load/store/flush functions)
 */

#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

#include <mcuxClKey.h>
#include <mcuxClRandom.h>
#include <mcuxClSession.h>
#include <mcuxClToolchain.h>

#include <mcuxClEcc_KeyEncodingMechanisms.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_KeyHelper.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClEcc_FeatureConfig.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMemory_Copy_Reversed_Internal.h>
#include <internal/mcuxClMemory_CopySecure_Internal.h>
#include <internal/mcuxClMemory_CopySecure_Reversed_Internal.h>
#include <internal/mcuxClSession_Internal.h>


/**********************************************************/
/* ECC key load functions                                 */
/**********************************************************/

/**
 * @brief Key load function for WeierECC private keys in plain encoding.
 *        If spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE it securely copies key->container.pData to *ppDest.
 *
 * @param[in]   session        Handle of the current session
 * @param[in]   key            Key handle that provides information to load the key
 * @param[out]  ppDest         Pointer-pointer to the destination key location
 * @param[in]   pKeyChecksums  Storing data needed for key checksum generation
 * @param[in]   spec           Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_WeierECC_PrivateKeyLoad_Plain, mcuxClKey_LoadFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_WeierECC_PrivateKeyLoad_Plain(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClKey_Handle_t key,
                                                          uint8_t **ppDest,
                                                          mcuxClKey_KeyChecksum_t *pKeyChecksums UNUSED_PARAM,
                                                          mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_WeierECC_PrivateKeyLoad_Plain);

  /* If spec specifies to securely copy a private key in BE and convert it to LE. */
  if (MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    uint8_t *pKeyData = mcuxClKey_getKeyData(key);
    uint8_t *pDest = *ppDest;
    uint32_t keyLength = mcuxClKey_getSize(key);

    /* Record input data for mcuxClMemory_copy_secure_reversed_int() */
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyBELoad, pDest);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyBELoad, pKeyData);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyBELoad, keyLength);

    /* Securely copy the private key to *pDest, reversing its endianness */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_reversed_int(pDest, pKeyData, keyLength));
  }
  /* spec is not valid */
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLECC_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_WeierECC_PrivateKeyLoad_Plain,
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_reversed_int)));
}

/**
 * @brief Key load function for WeierECC public keys in plain encoding.
 *        If spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_NORMALit copies key->container.pData to *ppDest.
 *
 * @param[in]   session        Handle of the current session
 * @param[in]   key            Key handle that provides information to load the key
 * @param[out]  ppDest         Pointer-pointer to the destination key location
 * @param[in]   pKeyChecksums  Storing data needed for key checksum generation
 * @param[in]   spec           Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_WeierECC_PublicKeyLoad_Plain, mcuxClKey_LoadFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_WeierECC_PublicKeyLoad_Plain(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClKey_Handle_t key,
                                                          uint8_t **ppDest,
                                                          mcuxClKey_KeyChecksum_t *pKeyChecksums UNUSED_PARAM,
                                                          mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_WeierECC_PublicKeyLoad_Plain);

  /* If spec specifies to copy the key data to ppDest. */
  if (MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    uint8_t *pDest = *ppDest;
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    const uint32_t bufferSize = operandSize + MCUXCLPKC_WORDSIZE;
    const uint32_t coordLength = mcuxClKey_getSize(key) / 2u; // get the length of a public key coordinate
    uint8_t *pPubKeyDestX = pDest;
    uint8_t *pPubKeyDestY = pDest + bufferSize;
    const uint8_t *pPubKeySrcX = mcuxClKey_getKeyData(key);
    const uint8_t *pPubKeySrcY = pPubKeySrcX + coordLength;

    /* Record input data for mcuxClMemory_copy_reversed_int() */
    MCUX_CSSL_DI_RECORD(copyPubKeyX, pPubKeyDestX);
    MCUX_CSSL_DI_RECORD(copyPubKeyX, pPubKeySrcX);
    MCUX_CSSL_DI_RECORD(copyPubKeyX, coordLength);
    MCUX_CSSL_DI_RECORD(copyPubKeyY, pPubKeyDestY);
    MCUX_CSSL_DI_RECORD(copyPubKeyY, pPubKeySrcY);
    MCUX_CSSL_DI_RECORD(copyPubKeyY, coordLength);

    /* Copy the public key to *pDest, reversing its endianness */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_reversed_int(pPubKeyDestX, pPubKeySrcX, coordLength));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_reversed_int(pPubKeyDestY, pPubKeySrcY, coordLength));
  }
  /* spec is not valid */
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLECC_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_WeierECC_PublicKeyLoad_Plain,
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_reversed_int),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_reversed_int)));
}

/**
 * @brief Key load function for EdDSA private and auxiliary secret keys in plain encoding.
 *        If spec action == MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEYHALFHASH_PTR it sets *ppDest to the private key half hash data in key->container.pData.
 *        If spec action == MCUXCLECC_ENCODING_SPEC_EDDSA_SUBPRIVKEY_LOAD_SECURE it securely copies the sub private key data in key->container.pData to *ppDest.
 *
 * @param[in]   session        Handle of the current session
 * @param[in]   key            Key handle that provides information to load the key
 * @param[out]  ppDest         Pointer-pointer to the destination key location
 * @param[in]   pKeyChecksums  Storing data needed for key checksum generation
 * @param[in]   spec           Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_PrivateKeyLoad_Plain, mcuxClKey_LoadFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_EdDSA_PrivateKeyLoad_Plain(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClKey_Handle_t key,
                                                          uint8_t **ppDest,
                                                          mcuxClKey_KeyChecksum_t *pKeyChecksums UNUSED_PARAM,
                                                          mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_PrivateKeyLoad_Plain);

  mcuxClEcc_EdDSA_DomainParams_t * const pDomainParams = (mcuxClEcc_EdDSA_DomainParams_t *) mcuxClKey_getTypeInfo(key);
  const uint32_t privKeyLength = (uint32_t) pDomainParams->b / 8u;
  const uint32_t subPrivKeyLength = ((uint32_t) pDomainParams->t + 7u) >> 3u;
  uint8_t *pKeyData = mcuxClKey_getKeyData(key);

  /* If spec specifies to set the key pointer to ppDest for the EdDSA private key half hash */
  if (MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEYHALFHASH_PTR == (spec & MCUXCLKEY_ENCODING_SPEC_COMP_MASK))
  {
    *ppDest = pKeyData + privKeyLength + subPrivKeyLength;
  }
  /* If spec specifies to securely copy the sub private key to ppDest. */
  else if (MCUXCLECC_ENCODING_SPEC_EDDSA_SUBPRIVKEY_LOAD_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_COMP_MASK))
  {
    uint8_t *pDest = *ppDest;
    uint8_t *pSubPrivKeyData = pKeyData + privKeyLength;

    /* Record input data for mcuxClMemory_copy_secure_int() */
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyLELoad, pDest);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyLELoad, pSubPrivKeyData);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyLELoad, subPrivKeyLength);

    /* Securely copy the sub private key to pDest. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(pDest, pSubPrivKeyData, subPrivKeyLength));
  }
  /* spec is not valid */
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLECC_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_EdDSA_PrivateKeyLoad_Plain,
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLECC_ENCODING_SPEC_EDDSA_SUBPRIVKEY_LOAD_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_COMP_MASK),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int)));
}


/**********************************************************/
/* ECC key store functions                                */
/**********************************************************/

#if defined(MCUXCLECC_FEATURE_INTERNAL_WEIER_PUBKEY_STORAGE)
/**
 * @brief Key store function for WeierECC private keys in plain encoding.
 *
 * @param[in]   session  Handle of the current session
 * @param[in]   key      Key handle that provides information to load the key
 * @param[out]  pSrc     Pointer to the source key location
 * @param[in]   spec     Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_WeierECC_PrivateKeyStore_Plain, mcuxClKey_StoreFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_WeierECC_PrivateKeyStore_Plain(
                                                          mcuxClSession_Handle_t session UNUSED_PARAM,
                                                          mcuxClKey_Handle_t key,
                                                          const uint8_t *pSrc,
                                                          mcuxClKey_Encoding_Spec_t spec UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_WeierECC_PrivateKeyStore_Plain);

  uint8_t *pKeyData = mcuxClKey_getKeyData(key);
  uint32_t keyLength = mcuxClKey_getSize(key);

  /* Record input data for mcuxClMemory_copy_secure_reversed_int() */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyStore, pKeyData);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyStore, pSrc);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyStore, keyLength);

  /* Securely copy the WeierECC private key to pKeyData. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_reversed_int(pKeyData, pSrc, keyLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_WeierECC_PrivateKeyStore_Plain,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_reversed_int));
}
#endif /* defined(MCUXCLECC_FEATURE_INTERNAL_WEIER_PUBKEY_STORAGE) */

#if defined(MCUXCLECC_FEATURE_INTERNAL_WEIER_PRIVKEY_STORAGE)
/**
 * @brief Key store function for WeierECC public keys in plain encoding.
 *
 * @param[in]   session  Handle of the current session
 * @param[in]   key      Key handle that provides information to load the key
 * @param[out]  pSrc     Pointer to the x-coordinate of the source public key (x,y). The y-coordinate is stored in PKC RAM
 *                       with offset bufferSize to pSrc
 * @param[in]   spec     Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_WeierECC_PublicKeyStore_Plain, mcuxClKey_StoreFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_WeierECC_PublicKeyStore_Plain(
                                                          mcuxClSession_Handle_t session UNUSED_PARAM,
                                                          mcuxClKey_Handle_t key,
                                                          const uint8_t *pSrc,
                                                          mcuxClKey_Encoding_Spec_t spec UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_WeierECC_PublicKeyStore_Plain);

  uint8_t *pKeyData = mcuxClKey_getKeyData(key);
  uint32_t keyLength = mcuxClKey_getSize(key);

  /* Copy the WeierECC public key x-coordinate to pKeyData. */
  const uint8_t *pPubKeySrcX = pSrc;
  uint8_t *pPubKeyDestX = pKeyData;
  const uint32_t coordLength = keyLength / 2u;
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int_PublicKeyStoreX, pPubKeyDestX);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int_PublicKeyStoreX, pPubKeySrcX);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int_PublicKeyStoreX, coordLength);
  MCUXCLPKC_WAITFORFINISH();
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_reversed_int(pPubKeyDestX, pPubKeySrcX, coordLength));

  /* Copy the WeierECC public key y-coordinate to pKeyData behind the x-coordinate. */
  const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
  const uint32_t bufferSize = operandSize + MCUXCLPKC_WORDSIZE;
  const uint8_t *pPubKeySrcY = pSrc + bufferSize;
  uint8_t *pPubKeyDestY = pKeyData + coordLength;
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int_PublicKeyStoreY, pPubKeyDestY);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int_PublicKeyStoreY, pPubKeySrcY);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_int_PublicKeyStoreY, coordLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_reversed_int(pPubKeyDestY, pPubKeySrcY, coordLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_WeierECC_PublicKeyStore_Plain,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_reversed_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_reversed_int));
}
#endif /* defined(MCUXCLECC_FEATURE_INTERNAL_WEIER_PRIVKEY_STORAGE) */

/**
 * @brief Key store function for EdDSA private and auxiliary secret keys in plain encoding.
 *        If spec action == MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEY_STORE_SECURE it stores the private key data in key->container.pData.
 *        If spec action == MCUXCLECC_ENCODING_SPEC_EDDSA_SUBPRIVKEY_STORE_SECURE it stores the sub private key data in key->container.pData.
 *        If spec action == MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEYHALFHASH_STORE_SECURE it stores the private key half hash data in key->container.pData.
 *
 * @param[in]   session  Handle of the current session
 * @param[in]   key      Key handle that provides information to load the key
 * @param[out]  pSrc     Pointer to the source key
 * @param[in]   spec     Specifications about the used key
 *
 * @return status
 * @retval MCUXCLKEY_STATUS_OK               On success
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_PrivateKeyStore_Plain, mcuxClKey_StoreFuncPtr_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_EdDSA_PrivateKeyStore_Plain(
                                                          mcuxClSession_Handle_t session,
                                                          mcuxClKey_Handle_t key,
                                                          const uint8_t *pSrc,
                                                          mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_PrivateKeyStore_Plain);

  mcuxClEcc_EdDSA_DomainParams_t * const pDomainParams = (mcuxClEcc_EdDSA_DomainParams_t *) mcuxClKey_getTypeInfo(key);
  const uint32_t privKeyLength = (uint32_t) pDomainParams->b / 8u;
  const uint32_t subPrivKeyLength = ((uint32_t) pDomainParams->t + 7u) >> 3u;
  uint8_t *pKeyData = mcuxClKey_getKeyData(key);
  uint8_t *pDest = NULL;
  uint32_t keyLength = 0;

  /* If spec specifies to store the private key */
  if (MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEY_STORE_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_COMP_MASK))
  {
      pDest = pKeyData;
      keyLength = privKeyLength;
  }
  /* If spec specifies to store the sub private key */
  else if (MCUXCLECC_ENCODING_SPEC_EDDSA_SUBPRIVKEY_STORE_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_COMP_MASK))
  {
      pDest = &pKeyData[privKeyLength];
      keyLength = subPrivKeyLength;
  }
  /* If spec specifies to store the private key half hash */
  else if (MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEYHALFHASH_STORE_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_COMP_MASK))
  {
      pDest = &pKeyData[privKeyLength + subPrivKeyLength];
      keyLength = privKeyLength;
  }
  /* spec is not valid */
  else
  {
      MCUXCLSESSION_FAULT(session, MCUXCLECC_STATUS_FAULT_ATTACK);
  }

  /* Record input data for mcuxClMemory_copy_secure_int() */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyLELoad, pDest);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyLELoad, pSrc);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_PrivateKeyLELoad, keyLength);

  /* Securely copy the sub private key to pDest. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(pDest, pSrc, keyLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_EdDSA_PrivateKeyStore_Plain,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
}

/**********************************************************/
/* ECC key encoding descriptors                           */
/**********************************************************/

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
/**
 * @brief Plain key encoding descriptor for WeierECC private keys.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_WeierECC_PrivateKey_Plain = {&mcuxClEcc_WeierECC_PrivateKeyLoad_Plain,
                                                                                             &mcuxClEcc_WeierECC_PrivateKeyStore_Plain,
                                                                                             NULL,
                                                                                             NULL,
                                                                                             MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                                 mcuxClEcc_WeierECC_PrivateKeyLoad_Plain),
                                                                                             MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                                 mcuxClEcc_WeierECC_PrivateKeyStore_Plain),
                                                                                             0u,
                                                                                             0u};

/**
 * @brief Plain key encoding descriptor for WeierECC public keys.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_WeierECC_PublicKey_Plain = {&mcuxClEcc_WeierECC_PublicKeyLoad_Plain,
                                                                                            &mcuxClEcc_WeierECC_PublicKeyStore_Plain,
                                                                                            NULL,
                                                                                            NULL,
                                                                                            MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                                mcuxClEcc_WeierECC_PublicKeyLoad_Plain),
                                                                                            MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                                mcuxClEcc_WeierECC_PublicKeyStore_Plain),
                                                                                            0u,
                                                                                            0u};

/**
 * @brief Plain key encoding descriptor for MontDH private keys.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_MontDH_PrivateKey_Plain = {&mcuxClKey_KeyLoad_Plain,
                                                                                           &mcuxClKey_KeyStore_Plain,
                                                                                           NULL,
                                                                                           NULL,
                                                                                           MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                               mcuxClKey_KeyLoad_Plain),
                                                                                           MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                               mcuxClKey_KeyStore_Plain),
                                                                                           0u,
                                                                                           0u};

/**
 * @brief Plain key encoding descriptor for MontDH public keys.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_MontDH_PublicKey_Plain = {&mcuxClKey_KeyLoad_Plain,
                                                                                          &mcuxClKey_KeyStore_Plain,
                                                                                          NULL,
                                                                                          NULL,
                                                                                          MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                              mcuxClKey_KeyLoad_Plain),
                                                                                          MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                              mcuxClKey_KeyStore_Plain),
                                                                                          0u,
                                                                                          0u};

/**
 * @brief Plain key encoding descriptor for EdDSA private keys.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_EdDSA_PrivateKey_Plain = {&mcuxClEcc_EdDSA_PrivateKeyLoad_Plain,
                                                                                          &mcuxClEcc_EdDSA_PrivateKeyStore_Plain,
                                                                                          NULL,
                                                                                          NULL,
                                                                                          MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                              mcuxClEcc_EdDSA_PrivateKeyLoad_Plain),
                                                                                          MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                              mcuxClEcc_EdDSA_PrivateKeyStore_Plain),
                                                                                          0u,
                                                                                          0u};

/**
 * @brief Plain key encoding descriptor for EdDSA public keys.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClEcc_EncodingDescriptor_EdDSA_PublicKey_Plain = {&mcuxClKey_KeyLoad_Plain,
                                                                                         &mcuxClKey_KeyStore_Plain,
                                                                                         NULL,
                                                                                         NULL,
                                                                                         MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                             mcuxClKey_KeyLoad_Plain),
                                                                                         MCUX_CSSL_FP_FUNCTION_CALLED(
                                                                                             mcuxClKey_KeyStore_Plain),
                                                                                         0u,
                                                                                         0u};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
