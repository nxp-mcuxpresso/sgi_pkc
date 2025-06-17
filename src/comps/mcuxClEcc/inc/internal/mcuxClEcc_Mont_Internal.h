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

/**
 * @file  mcuxClEcc_Mont_Internal.h
 * @brief internal header of mcuxClEcc MontDH functionalities
 */


#ifndef MCUXCLECC_MONT_INTERNAL_H_
#define MCUXCLECC_MONT_INTERNAL_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClEcc_Types.h>
#include <mcuxClKey_Types.h>
#include <internal/mcuxClPkc_Internal.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Mont_Internal_PkcWaLayout.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************/
/* Internal return codes for MontDH functions             */
/**********************************************************/
// None


/**********************************************************/
/* Internal MontDH defines                                */
/**********************************************************/

/** Use 4-byte (32-bit) multiplicative blinding in MontDH. */
#define MCUXCLECC_MONTDH_SCALAR_BLINDING_BYTELEN  4u

/** Input points shall be randomized by a random Z-coordinate then re-randomized every 8th iteration in Montgomery ladder. */
#define MCUXCLECC_MONTDH_RERANDOMIZED_ITERATION_INTERVAL  8u

/**********************************************************/
/* Internal MontDH types                                  */
/**********************************************************/

/**
 * Domain parameter structure for MontDH functions.
 */
struct mcuxClEcc_MontDH_DomainParams
{
    mcuxClEcc_CommonDomainParams_t common;  ///< structure containing pointers and lengths for common ECC parameters (see Common ECC Domain parameters)
    uint16_t c;     ///< cofactor exponent
    uint16_t t;     ///< bit position of MSBit of decoded scalar
};


/* Curve25519 domain parameters */
extern const mcuxClEcc_MontDH_DomainParams_t mcuxClEcc_MontDH_DomainParams_Curve25519;

/* Curve448 domain parameters */
extern const mcuxClEcc_MontDH_DomainParams_t mcuxClEcc_MontDH_DomainParams_Curve448;


/**********************************************************/
/* Declarations for internal MontDH functions             */
/**********************************************************/

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_MontDH_SetupEnvironment)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_MontDH_SetupEnvironment(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_MontDH_DomainParams_t *pDomainParams,
    uint8_t noOfBuffers
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_Mont_SecureScalarMult_XZMontLadder)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_Mont_SecureScalarMult_XZMontLadder(
    mcuxClSession_Handle_t pSession,
    uint8_t iScalar,
    uint32_t scalarBitLength,
    uint32_t optionAffineOrProjective
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_MontDH_X)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_MontDH_X(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_MontDH_DomainParams_t *pDomainParameters,
    const uint8_t *pCoordinateUEnc
    );


/**********************************************************/
/* Define internal MontDH functions                       */
/**********************************************************/

/**
 * @brief Implements ECC key pair generation step for a MontDH key agreement according to rfc7748.
 *
 * This function performs elliptic curve key generation of the private key and calculates corresponding public key for MontDH key agreement
 * as specified in rfc7748.
 * This API does not check if the curve parameters are correct.
 * This API might return MCUXCLECC_STATUS_RNG_ERROR when RNG behave in unexpected way
 * Unexpected behavior will return MCUXCLECC_STATUS_FAULT_ATTACK.
 *
 * @param[in] pSession          pointer to #mcuxClSession_Descriptor.
 * @param[in] generation        pointer to #mcuxClKey_GenerationDescriptor.
 * @param[out] privKey          private key handling structure
 * @param[out] pubKey           public key handling structure
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_MontDH_GenerateKeyPair, mcuxClKey_KeyGenFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_MontDH_GenerateKeyPair(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Generation_t generation,
    mcuxClKey_Handle_t privKey,
    mcuxClKey_Handle_t pubKey
    );

/**
 * @brief Implements the MontDH key agreement according to rfc7748.
 *
 * This function performs a MontDH key agreement to compute a shared secret between two parties using according to Curve25519 or Curve448 as specified in rfc7748.
 * This API does not check if the curve parameters are correct.
 * This API might return MCUXCLECC_STATUS_RNG_ERROR when RNG behave in unexpected way
 * This API might return MCUXCLECC_STATUS_ERROR_SMALL_SUBGROUP if generated public key lies in the small subgroup
 * Unexpected behavior will return MCUXCLECC_STATUS_FAULT_ATTACK.
 *
 * @param[in] pSession             pointer to #mcuxClSession_Descriptor.
 * @param[in] agreement            Key agreement algorithm specifier.
 * @param[in] key                  private key handling structure
 * @param[in] otherKey             public key handling structure
 * @param[in] additionalInputs     Key agreement additional input pointers (unused parameter)
 * @param[in] numberOfInputs       number of additional inputs (unused parameter)
 * @param[out] pOut                buffer for shared secret
 * @param[out] pOutLength          shared secret length
 *
 * @attention This function uses PRNG. Caller needs to check if PRNG is ready.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_MontDH_KeyAgreement, mcuxClKey_AgreementFct_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_MontDH_KeyAgreement(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Agreement_t agreement,
    mcuxClKey_Handle_t key,
    mcuxClKey_Handle_t otherKey,
    mcuxClKey_Agreement_AdditionalInput_t additionalInputs[],
    uint32_t numberOfInputs,
    uint8_t * pOut,
    uint32_t * const pOutLength
    );

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_MONT_INTERNAL_H_ */
