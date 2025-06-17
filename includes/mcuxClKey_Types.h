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
 * @file  mcuxClKey_Types.h
 * @brief Type definitions for the mcuxClKey component
 */

#ifndef MCUXCLKEY_TYPES_H_
#define MCUXCLKEY_TYPES_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * TYPEDEFS
 **********************************************/
/**
 * @defgroup mcuxClKey_Types mcuxClKey_Types
 * @brief Defines all types of @ref mcuxClKey
 * @ingroup mcuxClKey
 * @{
 */

/**
 * @brief Type for Key component error codes.
 */
typedef uint32_t mcuxClKey_Status_t;

/**
 * @brief Type for algorithm based key id.
 */
typedef uint32_t mcuxClKey_AlgorithmId_t;

/**
 * @brief Type for algorithm based key size.
 */
typedef uint32_t mcuxClKey_Size_t;

/**
 * @brief Type for encoding based key id.
 */
typedef uint32_t mcuxClKey_Encoding_Spec_t;

/**
 * @brief Deprecated type for Key component error codes, returned by functions with code-flow protection.
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_Status_Encoded_t;

/* Forward declaration */
struct mcuxClKey_Encoding;

/**
 * @brief Forward declaration for Key descriptor structure
 *
 * This structure captures all the information that the Key interfaces need
 * to know about a particular key.
 */
struct mcuxClKey_Descriptor;

/**
 * @brief Key descriptor type
 *
 * This type captures all the information that the Key interfaces need to know
 * about a particular Key.
 */
typedef struct mcuxClKey_Descriptor mcuxClKey_Descriptor_t;

/**
 * @brief Key handle type
 *
 * This type is used to refer to the opaque key descriptor.
 */
typedef mcuxClKey_Descriptor_t * const mcuxClKey_Handle_t;

/**
 * @brief Forward declaration for Key type structure
 *
 * This structure captures all the information that the Key interfaces need to
 * know about a particular Key type.
 */
struct mcuxClKey_TypeDescriptor;

/**
 * @brief Key type descriptor type
 *
 * This type captures all the information that the Key interfaces need to know
 * about a particular Key type.
 */
typedef struct mcuxClKey_TypeDescriptor mcuxClKey_TypeDescriptor_t;

/**
 * @brief Key type handle type
 *
 * This type is used to refer to a key type descriptor.
 */
typedef const mcuxClKey_TypeDescriptor_t * mcuxClKey_Type_t;

/**
 * @brief Custom key type handle type
 *
 * This type is used to refer to a custom key type descriptor.
 */
typedef mcuxClKey_TypeDescriptor_t * mcuxClKey_CustomType_t;

/**
 * @brief Key encoding mechanism descriptor structure
 *
 * This structure captures all the information that the Key interfaces need to
 * know about a particular Key encoding mechanism.
 */
struct mcuxClKey_EncodingDescriptor;

/**
 * @brief Key encoding mechanism descriptor type
 *
 * This type captures all the information that the Key interfaces need to know
 * about a particular Key encoding mechanism.
 */
typedef struct mcuxClKey_EncodingDescriptor mcuxClKey_EncodingDescriptor_t;

/**
 * Key encoding mechanism type
 *
 * This type is used to refer to a Key encoding mechanism.
 */
typedef const mcuxClKey_EncodingDescriptor_t * mcuxClKey_Encoding_t;

/**
 * @brief Key agreement additional input pointers
 */
struct mcuxClKey_Agreement_AdditionalInput{
  mcuxCl_InputBuffer_t input;
  uint32_t size;
};

typedef struct mcuxClKey_Agreement_AdditionalInput mcuxClKey_Agreement_AdditionalInput_t;

/**
 * @brief Key agreement descriptor structure
 *
 * This structure captures all the information that the Key interfaces need to
 * know about a particular Key agreement algorithm.
 */
struct mcuxClKey_AgreementDescriptor;

/**
 * @brief Key agreement descriptor type
 *
 * This type captures all the information that the Key interfaces need to know
 * about a particular Key agreement algorithm.
 */
typedef struct mcuxClKey_AgreementDescriptor mcuxClKey_AgreementDescriptor_t;

/**
 * @brief Key agreement type
 *
 * This type is used to refer to a Key agreement algorithm.
 */
typedef const mcuxClKey_AgreementDescriptor_t * const mcuxClKey_Agreement_t;


/**
 * @brief Key generation descriptor structure
 *
 * This structure captures all the information that the Key interfaces need to
 * know about a particular Key generation algorithm.
 */
struct mcuxClKey_GenerationDescriptor;

/**
 * @brief Key generation descriptor type
 *
 * This type captures all the information that the Key interfaces need to know
 * about a particular Key generation algorithm.
 */
typedef struct mcuxClKey_GenerationDescriptor mcuxClKey_GenerationDescriptor_t;

/**
 * @brief Key generation type
 *
 * This type is used to refer to a Key generation algorithm.
 */
typedef const mcuxClKey_GenerationDescriptor_t * const mcuxClKey_Generation_t;


/**
 * @brief Forward declaration for generic key validation descriptor structure.
 */
struct mcuxClKey_ValidationDescriptor;

/**
 * @brief Generic key validation descriptor type.
 */
typedef struct mcuxClKey_ValidationDescriptor mcuxClKey_ValidationDescriptor_t;

/**
 * @brief Generic key validation type.
 */
typedef const mcuxClKey_ValidationDescriptor_t * const mcuxClKey_Validation_t;

/**
 * @}
 */ /* mcuxClKey_Types */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKEY_TYPES_H_ */
