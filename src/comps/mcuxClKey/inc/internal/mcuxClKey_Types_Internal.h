/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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
 * @file  mcuxClKey_Types_Internal.h
 * @brief Type definitions for the mcuxClKey component
 */

#ifndef MCUXCLKEY_TYPES_INTERNAL_H_
#define MCUXCLKEY_TYPES_INTERNAL_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>


#ifdef __cplusplus
extern "C" {
#endif
/**********************************************
 * FUNCTION TYPE DEFINITIONS
 **********************************************/
struct mcuxClKey_KeyChecksum;
typedef struct mcuxClKey_KeyChecksum mcuxClKey_KeyChecksum_t;
/**
 * @brief Functions to load a key into coprocessor or memory buffer.
 *
 * @param[in]  session        Handle of the current session
 * @param[in]  key            Key handle that provides information to load the key
 * @param[out] ppDest         Pointer-pointer to the destination key location
 * @param[in]  pKeyChecksums  Storing data needed for key checksum generation
 * @param      spec           Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKey_LoadFuncPtr_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClKey_LoadFuncPtr_t)(mcuxClSession_Handle_t session, mcuxClKey_Handle_t key, uint8_t **ppDest, mcuxClKey_KeyChecksum_t * pKeyChecksums, mcuxClKey_Encoding_Spec_t spec));

/**
 * @brief Functions to store a key.
 *
 * @param[in]   session  Handle of the current session
 * @param[out]  key      Key handle that provides information to store the key
 * @param[in]   pSrc     Pointer to the source key location
 * @param       spec     Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKey_StoreFuncPtr_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClKey_StoreFuncPtr_t)(mcuxClSession_Handle_t session, mcuxClKey_Handle_t key, const uint8_t *pSrc, mcuxClKey_Encoding_Spec_t spec));

/**
 * @brief Functions to flush a key from coprocessor or memory buffer.
 *
 * @param[in]  session  Handle of the current session
 * @param[out] key      Key handle that provides information to flush the key
 * @param      spec     Specifications about the used key
 *
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKey_FlushFuncPtr_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClKey_FlushFuncPtr_t)(mcuxClSession_Handle_t session, mcuxClKey_Handle_t key, mcuxClKey_Encoding_Spec_t spec));

/**
 * @brief Functions to handling key checksums.
 *
 * @param[in]  session        Handle of the current session
 * @param[in]  pKeyChecksums  Storing data needed for key checksum generation
 * @param[in]  pKey           Pointer to key location, i.e. SGI KEY0-SFR
 *
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKey_HandleKeyChecksums_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClKey_HandleKeyChecksums_t)(mcuxClSession_Handle_t session, mcuxClKey_KeyChecksum_t * pKeyChecksums, uint8_t* pKey));


/**********************************************
 * DATA TYPE DEFINITIONS
 **********************************************/

/**
 * @brief Type for key load location options.
 */
typedef uint16_t mcuxClKey_LoadStatus_t;


/**********************************************
 * STRUCTURES
 **********************************************/

/**
 * @brief Struct for storing data needed for key checksum generation
 */
struct mcuxClKey_KeyChecksum {
    uint32_t data[2]; // reference data. For AES keys: data[0] = crc16, data[1] = sfrSeed
    uint32_t keyLength;
    mcuxClKey_HandleKeyChecksums_t VerifyFunc;
    uint32_t protectionToken_VerifyFunc;
};

/**
 * @brief Struct to map algorithm id and size.
 */
struct mcuxClKey_TypeDescriptor {
  mcuxClKey_AlgorithmId_t    algoId;         ///< Identifier of the algorithm, refer to #mcuxClKey_KeyTypes
  mcuxClKey_Size_t           size;           ///< The key size for the key type in bytes, refer to #mcuxClKey_KeySize
  void *                    info;           ///< Pointer to additional information for this key type (e.g. curve parameters, public exponent)
  mcuxClKey_Encoding_t       plainEncoding;  ///< Default (plain) encoding for this key type
};

/**
 * @brief Struct for key internal storage information (destination key)
 * Key data can be provided in @param pData or loaded to a @param slot
 * @param status is one of MCUXCLKEY_LOADSTATUS_
 */
typedef struct mcuxClKey_Location {
  uint8_t *             pData;    ///< Pointer to the data buffer
  uint32_t              length;   ///< Length of the data buffer
  uint32_t              slot;     ///< Key slot to which the key is loaded
  mcuxClKey_LoadStatus_t status;   ///< Load status of the key
  uint16_t              PADDING_FOR_32BIT_ALIGNMENT;
} mcuxClKey_Location_t;

/**
 * @brief Struct for key external storage information (source for mcuxClKey_Location_t)
 */
typedef struct mcuxClKey_Container {
  uint8_t *               pData;      ///< Pointer to the data buffer
  uint32_t                length;     ///< Length of the data buffer
  uint32_t                used;       ///< Length of the used part of the data buffer
  mcuxClKey_Descriptor_t * parentKey;  ///< Handle of the parent of the key
  const uint8_t *         pAuxData;       ///< Pointer to auxiliary data needed by the encoding, its type depends on the actual encoding implementation
  uint32_t                auxDataLength;  ///< Length of the auxiliary data
} mcuxClKey_Container_t;

/**
 * @brief Type for mapping load, store and flush functions.
 */
struct mcuxClKey_EncodingDescriptor {
  mcuxClKey_LoadFuncPtr_t    loadFunc;   ///< Function pointer to a load function
  mcuxClKey_StoreFuncPtr_t   storeFunc;  ///< Function pointer to a store function
  mcuxClKey_FlushFuncPtr_t   flushFunc;  ///< Function pointer to a flush function
  mcuxClKey_HandleKeyChecksums_t handleKeyChecksumsFunc;   ///< Function pointer to a key checksum function
  uint32_t protectionToken_loadFunc;         ///< Protection token of the load function
  uint32_t protectionToken_storeFunc;        ///< Protection token of the store function
  uint32_t protectionToken_flushFunc;        ///< Protection token of the flush function
  uint32_t protectionToken_handleKeyChecksumsFunc;     ///< Protection token of the checksum function
};

/**
 * @brief Struct of the key handle.
 */
struct mcuxClKey_Descriptor {
  mcuxClKey_Container_t                    container;   ///< Container for external (encoded) storage of the key, it cannot be used directly by an operation
  mcuxClKey_TypeDescriptor_t               type;        ///< Type of the key
  mcuxClKey_Location_t                     location;    ///< Location of the (decoded) key, ready for use
  const mcuxClKey_EncodingDescriptor_t *   encoding;    ///< Encoding applied to the key stored in the container
  void *                                  pLinkedData; ///< Pointer to auxiliary data linked to the key
};

/**
 * @brief Function prototype for protocol specific key generation function pointer.
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKey_KeyGenFct_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (* mcuxClKey_KeyGenFct_t)(
  mcuxClSession_Handle_t session,
  mcuxClKey_Generation_t generation,
  mcuxClKey_Handle_t privKey,
  mcuxClKey_Handle_t pubKey
));

/**
 * @brief Struct of generation descriptor
 */
struct mcuxClKey_GenerationDescriptor
{
  mcuxClKey_KeyGenFct_t pKeyGenFct;    ///< Pointer to the protocol specific key pair generation function
  uint32_t protectionTokenKeyGenFct;  ///< Protection token of the protocol specific key generation function
  const void *pProtocolDescriptor;    ///< Pointer to additional parameters for the protocol specific key generation function
};


/**
 * Generic key validate function descriptor structure.
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKey_ValidationFunction_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) (*mcuxClKey_ValidationFunction_t)(
    mcuxClSession_Handle_t session,   ///< Handle for the current CL session
    mcuxClKey_Handle_t key            ///< Handle for the key to be validated
));

struct mcuxClKey_ValidationDescriptor {
  mcuxClKey_ValidationFunction_t validateFct;
  uint32_t validateFct_FP_FuncId;
};

/**
 * Mode/Skeleton function types
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClKey_AgreementFct_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClKey_AgreementFct_t) (
    mcuxClSession_Handle_t session,
    mcuxClKey_Agreement_t agreement,
    mcuxClKey_Handle_t key,
    mcuxClKey_Handle_t otherKey,
    mcuxClKey_Agreement_AdditionalInput_t additionalInputs[],
    uint32_t numberOfInputs,
    uint8_t * pOut,
    uint32_t * const pOutLength
));

/**
 * @brief Key agreement descriptor structure
 *
 * This structure captures all the information that the Key interfaces need to
 * know about a particular Key agreement algorithm.
 */
struct mcuxClKey_AgreementDescriptor {
  mcuxClKey_AgreementFct_t   pAgreementFct;  ///< Pointer to the protocol specific key agreement function
  uint32_t protectionTokenAgreementFct;     ///< Protection token of the protocol specific key agreement function
  const void *pProtocolDescriptor;          ///< Pointer to additional parameters for the protocol specific key agreement function
};



#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKEY_TYPES_INTERNAL_H_ */
