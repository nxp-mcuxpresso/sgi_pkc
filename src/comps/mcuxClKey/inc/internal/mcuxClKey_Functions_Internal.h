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
 * @file  mcuxClKey_Functions_Internal.h
 * @brief Internal function definitions for the mcuxClKey component
 */

#ifndef MCUXCLKEY_FUNCTIONS_INTERNAL_H_
#define MCUXCLKEY_FUNCTIONS_INTERNAL_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxClKey_Types.h>
#include <mcuxClKey_Constants.h>
#include <internal/mcuxClKey_Types_Internal.h>

#ifdef __cplusplus
extern "C" {
#endif


/************************************************************
 * INTERNAL INLINED FUNCTIONS FOR PROPER TYPE CASTS         *
 ************************************************************/

/**
 * @brief Cast the key AuxData to a Key descriptor.
 *        This is needed for certain AES key encodings.
 *
 * @param key  The key handle to access
 *
 * @return A pointer to the key descriptor that stored in the key AuxData field.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getKeyDescriptorFromAuxData)
static inline const mcuxClKey_Descriptor_t* mcuxClKey_getKeyDescriptorFromAuxData(mcuxClKey_Handle_t key)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (const mcuxClKey_Descriptor_t *) key->container.pAuxData;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}


/************************************************************
 * INTERNAL INLINED FUNCTIONS TO ACCESS THE KEY DESCRIPTOR
 ************************************************************/

/**
 * @brief Returns the key data pointer of the key handle
 *
 * @return Key data pointer of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getKeyData)
static inline uint8_t * mcuxClKey_getKeyData(mcuxClKey_Handle_t key)
{
  return key->container.pData;
}

/**
 * @brief Sets the key data pointer of the key handle
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setKeyData)
static inline void mcuxClKey_setKeyData(mcuxClKey_Handle_t key, uint8_t * pKeyData)
{
  key->container.pData = pKeyData;
}


/**
 * @brief Returns the aux data pointer of the key handle
 *
 * @return Aux data pointer of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getAuxData)
static inline const uint8_t * mcuxClKey_getAuxData(mcuxClKey_Handle_t key)
{
  return key->container.pAuxData;
}

/**
 * @brief Sets the aux data pointer of the key handle
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setAuxData)
static inline void mcuxClKey_setAuxData(mcuxClKey_Handle_t key, const uint8_t * pAuxData)
{
  key->container.pAuxData = pAuxData;
}


/**
 * @brief Returns the aux data length of the key handle
 *
 * @return Aux data length of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getAuxDataLength)
static inline uint32_t mcuxClKey_getAuxDataLength(mcuxClKey_Handle_t key)
{
  return key->container.auxDataLength;
}

/**
 * @brief Sets the aux data length of the key handle
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setAuxDataLength)
static inline void mcuxClKey_setAuxDataLength(mcuxClKey_Handle_t key, uint32_t auxDataLength)
{
  key->container.auxDataLength = auxDataLength;
}


/**
 * @brief Sets the protection descriptor pointer of the key handle
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setEncodingType)
static inline void mcuxClKey_setEncodingType(mcuxClKey_Handle_t key, const mcuxClKey_EncodingDescriptor_t * pEncoding)
{
  key->encoding = pEncoding;
}

/**
 * @brief Returns the linked data pointer of the key handle
 *
 * @return linked data pointer of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getLinkedData)
static inline void * mcuxClKey_getLinkedData(mcuxClKey_Handle_t key)
{
  return key->pLinkedData;
}

/**
 * @brief Sets the linked data pointer of the key handle
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setLinkedData)
static inline void mcuxClKey_setLinkedData(mcuxClKey_Handle_t key, void * pLinkedData)
{
  key->pLinkedData = pLinkedData;
}

/**
 * @brief Gets the type structure of the key handle
 *
 * @return Type structure of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getTypeDescriptor)
static inline mcuxClKey_TypeDescriptor_t mcuxClKey_getTypeDescriptor(mcuxClKey_Handle_t key)
{
  return key->type;
}

/**
 * @brief Sets the type structure of the key handle
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setTypeDescriptor)
static inline void mcuxClKey_setTypeDescriptor(mcuxClKey_Handle_t key, mcuxClKey_TypeDescriptor_t pType)
{
  key->type = pType;
}


/**
 * @brief Gets the type info field of the key handle, which might contain pointer to ECC domain parameters
 *
 * @return Type info of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getTypeInfo)
static inline void * mcuxClKey_getTypeInfo(mcuxClKey_Handle_t key)
{
  return key->type.info;
}


/**
 * @brief Returns the key size in bytes of the key handle
 *
 * @return Key size in bytes of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getSize)
static inline mcuxClKey_Size_t mcuxClKey_getSize(mcuxClKey_Handle_t key)
{
  return key->type.size;
}


/**
 * @brief Returns the algorithm identifier of the key handle
 *
 * @return Algorithm identifier of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getAlgoId)
static inline mcuxClKey_AlgorithmId_t mcuxClKey_getAlgoId(mcuxClKey_Handle_t key)
{
  return key->type.algoId;
}

/**
 * @brief Returns the algorithm of the key handle
 *
 * @return Algorithm identifier of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getAlgorithm)
static inline mcuxClKey_AlgorithmId_t mcuxClKey_getAlgorithm(mcuxClKey_Handle_t key)
{
  return key->type.algoId & MCUXCLKEY_ALGO_ID_ALGO_MASK;
}

/**
 * @brief Returns the key usage of the key handle
 *
 * @return Algorithm identifier of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getKeyUsage)
static inline mcuxClKey_AlgorithmId_t mcuxClKey_getKeyUsage(mcuxClKey_Handle_t key)
{
  return key->type.algoId & MCUXCLKEY_ALGO_ID_USAGE_MASK;
}


/**
 * @brief Returns the pointer of the loaded key data of the key handle
 *
 * @return Pointer to the loaded key data
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getLoadedKeyData)
static inline uint8_t * mcuxClKey_getLoadedKeyData(mcuxClKey_Handle_t key)
{
  return key->location.pData;
}

/**
 * @brief Sets the pointer of the (to be) loaded key data
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setLoadedKeyData)
static inline void mcuxClKey_setLoadedKeyData(mcuxClKey_Handle_t key, uint32_t * pKeyDataLoadLocation)
{
  key->location.pData = (uint8_t *) pKeyDataLoadLocation;
}


/**
 * @brief Returns the length of the loaded key data
 *
 * @return Length of to the loaded key data of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getLoadedKeyLength)
static inline uint32_t mcuxClKey_getLoadedKeyLength(mcuxClKey_Handle_t key)
{
  return key->location.length;
}

/**
 * @brief Sets the length of the loaded key data
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setLoadedKeyLength)
static inline void mcuxClKey_setLoadedKeyLength(mcuxClKey_Handle_t key, uint32_t keyLength)
{
  key->location.length = keyLength;
}


/**
 * @brief Returns the hardware slot of the loaded key
 *
 * @return Hardware slot of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getLoadedKeySlot)
static inline uint32_t mcuxClKey_getLoadedKeySlot(const mcuxClKey_Descriptor_t* key)
{
  return key->location.slot;
}

/**
 * @brief Sets the pointer of the (to be) loaded data of the key handle
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setLoadedKeySlot)
static inline void mcuxClKey_setLoadedKeySlot(mcuxClKey_Handle_t key, uint32_t keySlot)
{
  key->location.slot = keySlot;
}


/**
 * @brief Returns the load status of the key handle
 *
 * @return Load status of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getLoadStatus)
static inline mcuxClKey_LoadStatus_t mcuxClKey_getLoadStatus(mcuxClKey_Handle_t key)
{
  return key->location.status;
}

/**
 * @brief Sets the load status of the key handle
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setLoadStatus)
static inline void mcuxClKey_setLoadStatus(mcuxClKey_Handle_t key, mcuxClKey_LoadStatus_t loadStatus)
{
  key->location.status = loadStatus;
}


/**
 * @brief Returns the pointer to the parent key of the key handle
 *
 * @return Pointer to the parent key of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getParentKey)
static inline mcuxClKey_Descriptor_t * mcuxClKey_getParentKey(mcuxClKey_Handle_t key)
{
  return key->container.parentKey;
}

/**
 * @brief Sets the pointer to the parent key of the key handle
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setParentKey)
static inline void mcuxClKey_setParentKey(mcuxClKey_Handle_t key, mcuxClKey_Descriptor_t * pParentKey)
{
  key->container.parentKey = pParentKey;
}


/**
 * @brief Returns the size of the key data container
 *
 * @return Size of the key data container of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getKeyContainerSize)
static inline uint32_t mcuxClKey_getKeyContainerSize(mcuxClKey_Handle_t key)
{
  return key->container.length;
}

/**
 * @brief Sets the size of the key data container of the given key
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setKeyContainerSize)
static inline void mcuxClKey_setKeyContainerSize(mcuxClKey_Handle_t key, uint32_t keyContainerSize)
{
  key->container.length = keyContainerSize;
}


/**
 * @brief Returns the used size of the key data container
 *
 * @return Used size of the key data container of the given key
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_getKeyContainerUsedSize)
static inline uint32_t mcuxClKey_getKeyContainerUsedSize(mcuxClKey_Handle_t key)
{
  return key->container.used;
}

/**
 * @brief Sets the used size of the key data container of the given key
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setKeyContainerUsedSize)
static inline void mcuxClKey_setKeyContainerUsedSize(mcuxClKey_Handle_t key, uint32_t keyContainerUsedSize)
{
  key->container.used = keyContainerUsedSize;
}

/************************************************************
 * INTERNAL INLINED FUNCTIONS FOR KEY FUNCTIONALITY
 ************************************************************/

/**
 * @brief Load (and decode) the key data to the destination. This is a wrapper for the
 * encoding specific loadFunc.
 *
 * @param[in]  session Handle of the current session
 * @param      key     Handle to the key to be loaded
 * @param[out] ppDest  Pointer-pointer to the destination key location
 * @param      spec    Specification of the load operation
 *
 * @post
 *  - Data integrity: see description of the component-specific loadFunc - TODO to be updated in CLNS-13431
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_load)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_load(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  uint8_t **ppDest,
  mcuxClKey_KeyChecksum_t * pKeyChecksums,
  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_load,
    key->encoding->protectionToken_loadFunc);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(key->encoding->loadFunc(session, key, ppDest, pKeyChecksums, spec));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_load);
}

/**
 * @brief Store (and encode/protect) the key data to the container. This is a wrapper for the
 * encoding specific storeFunc.
 *
 * @param[in]  session Handle of the current session
 * @param[out] key     Handle to the key to be stored
 * @param[in]  pSrc    Pointer to the source key location
 * @param      spec    Specification of the store operation
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_store)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_store(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  const uint8_t *pSrc,
  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_store,
    key->encoding->protectionToken_storeFunc);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(key->encoding->storeFunc(session, key, pSrc, spec));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_store);
}

/**
 * @brief Flush the key from its location. This is a wrapper for the
 * encoding specific flushFunc.
 *
 * @post On successful flush, the key handle is updated to reflect
 *       that the key is not longer loaded.
 *
 * @param         session Handle of the current session
 * @param[in,out] key     Handle to the key to be stored
 * @param         spec    Specification of the store operation
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_flush_internal)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_flush_internal(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_flush_internal,
    key->encoding->protectionToken_flushFunc);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(key->encoding->flushFunc(session, key, spec));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_flush_internal);
}


/************************************************************
 * INTERNAL FUNCTION DECLARATIONS FOR KEY FUNCTIONALITY
 ************************************************************/

/**
 * @brief Functions to load a key into coprocessor or memory buffer with plain key data.
 *
 * If spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_PTR, it sets *ppDest = key->container.pData,
 *        else if spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE, it securely copies the key from key->container.pData to *ppDest,
 *        else if spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL, it copies the key from key->container.pData to *ppDest,
 * else, invalid spec.
 *
 * @param[in]   session        Handle of the current session (unused)
 * @param[in]   key            Key handle that provides information to load the key
 * @param[out]  ppDest         Pointer-pointer to the destination key location
 * @param[in]   pKeyChecksums  Storing data needed for key checksum generation
 * @param       spec           Specifications about the used key (unused)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_KeyLoad_Plain, mcuxClKey_LoadFuncPtr_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_KeyLoad_Plain(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  uint8_t **ppDest,
  mcuxClKey_KeyChecksum_t * pKeyChecksums,
  mcuxClKey_Encoding_Spec_t spec
);

/**
 * @brief Functions to store a key into key container with plain key data.
 *
 * If spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_PTR, it sets key->container.pData = *ppSrc,
 *        else if spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE, it securely copies the key from *ppSrc to key->container.pData,
 *        else if spec action == MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL, it copies the key from *ppSrc to key->container.pData,
 * else, invalid spec.
 *
 * @param[in]    session        Handle of the current session (unused)
 * @param[out]   key            Key handle that provides information to store the key
 * @param[in]    pSrc           Pointer to the source key location
 * @param        spec           Specifications about the used key (unused)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_KeyStore_Plain, mcuxClKey_StoreFuncPtr_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_KeyStore_Plain(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  const uint8_t *pSrc,
  mcuxClKey_Encoding_Spec_t spec
);

/**
 * @brief Key checksum handling function for protection mechanisms without key checksums.
 *
 * @param[in]   session          Handle of the current session (unused)
 * @param[in]   pKeyChecksums    Storing data needed for key checksum generation
 * @param[in]   pKey             Pointer to key location
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_handleKeyChecksums_none, mcuxClKey_HandleKeyChecksums_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_handleKeyChecksums_none(
  mcuxClSession_Handle_t session,
  mcuxClKey_KeyChecksum_t * pKeyChecksums,
  uint8_t* pKey
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKEY_FUNCTIONS_INTERNAL_H_ */
