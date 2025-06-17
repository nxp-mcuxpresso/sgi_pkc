/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
 * @file mcuxClFfdh_Types.h
 * @brief Type definitions and descriptors of mcuxClFfdh component
 */


#ifndef MCUXCLFFDH_TYPES_H_
#define MCUXCLFFDH_TYPES_H_


#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClFfdh_Constants.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup mcuxClFfdh_Types mcuxClFfdh_Types
 * @brief Defines all types of @ref mcuxClFfdh
 * @ingroup mcuxClFfdh
 * @{
 */

/**
 * @brief Type for mcuxClFfdh component return codes.
 */
typedef uint32_t mcuxClFfdh_Status_t;

/** Type for FFDH domain parameters */
typedef struct mcuxClFfdh_DomainParams mcuxClFfdh_DomainParams_t;

/**
 * @}
 */ /* mcuxClFfdh_Types */

/**********************************************************/
/* Descriptors of mcuxClFfdh APIs                          */
/**********************************************************/

/**
 * @defgroup mcuxClFfdh_DomainParamsDescriptor mcuxClFfdh_DomainParamsDescriptor
 * @brief Definitions of domain parameters descriptors
 * @ingroup mcuxClFfdh_Descriptors
 * @{
 */


/* RFC7919 ffdhe2048 domain parameters descriptor */
extern const mcuxClFfdh_DomainParams_t mcuxClFfdh_domainParams_ffdhe2048;

/* RFC7919 ffdhe3072 domain parameters descriptor */
extern const mcuxClFfdh_DomainParams_t mcuxClFfdh_domainParams_ffdhe3072;

/* RFC7919 ffdhe4096 domain parameters descriptor */
extern const mcuxClFfdh_DomainParams_t mcuxClFfdh_domainParams_ffdhe4096;

/* RFC7919 ffdhe6144 domain parameters descriptor */
extern const mcuxClFfdh_DomainParams_t mcuxClFfdh_domainParams_ffdhe6144;

/* RFC7919 ffdhe8192 domain parameters descriptor */
extern const mcuxClFfdh_DomainParams_t mcuxClFfdh_domainParams_ffdhe8192;


/**
 * @}
 */ /* mcuxClFfdh_DomainParamsDescriptor */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLFFDH_TYPES_H_ */
