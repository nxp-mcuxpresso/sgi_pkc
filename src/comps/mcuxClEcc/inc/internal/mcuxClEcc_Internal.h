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
 * @file  mcuxClEcc_Internal.h
 * @brief internal header of mcuxClEcc functionalities
 */


#ifndef MCUXCLECC_INTERNAL_H_
#define MCUXCLECC_INTERNAL_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClSession.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClBuffer.h>
#include <mcuxClEcc_Types.h>
#include <mcuxClKey_Types.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClEcc_FeatureConfig.h>

#include <internal/mcuxClEcc_Internal_UPTRT_access.h>
#include <internal/mcuxClEcc_Internal_PkcWaLayout.h>

#ifdef __cplusplus
extern "C" {
#endif


/**********************************************************/
/*                                                        */
/* Internal return codes of mcuxClEcc                      */
/*                                                        */
/**********************************************************/

#define MCUXCLECC_INTSTATUS_SCALAR_ZERO              ((mcuxClEcc_Status_t) 0x55AA2E2Bu)
#define MCUXCLECC_INTSTATUS_POINTCHECK_NOT_OK        ((mcuxClEcc_Status_t) 0x55AA8917u)
#define MCUXCLECC_INTSTATUS_DECODING_NOT_OK          ((mcuxClEcc_Status_t) 0x55AA89A9u)

/* Rule of ECC return codes:
 * All return codes are of the format: 0x55XXYYTT
 * API         : XX = 55
 * Internal    : XX = AA
 * Code class : YY status code class according to mcuxClCore_Macros.h
 *                     NORMAL/NORMALMISMATCH/ABNORMAL/ATTACK
 * HammingWeight(TT) = 4, according to coding guidelines
 *
 * General  OK  : YYTT = 2E55
 * Fault Attack : 0x55AAF0F0
 */


/**********************************************************/
/*                                                        */
/* Definition of CPU workarea layout of ECC APIs          */
/*                                                        */
/**********************************************************/

MCUX_CSSL_ANALYSIS_START_SUPPRESS_FLEXIBLE_ARRAY("Due to project requirements ECC component needs to handle different usecases. In order to preserve memory flexible array is used. It is user responsibility to provide sufficient memory area using provided macros for each usecase.")
typedef struct
{
    uint32_t wordNumCpuWa;  /* number of words (uint32_t) used in CPU workarea */
    uint32_t wordNumPkcWa;  /* number of words (uint32_t) used in PKC workarea */
} mcuxClEcc_CpuWa_t;
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_FLEXIBLE_ARRAY()


/**********************************************************/
/*                                                        */
/* Definition of generic ECC domain parameters            */
/*                                                        */
/**********************************************************/

typedef struct mcuxClEcc_CommonDomainParams mcuxClEcc_CommonDomainParams_t;


/**
 * The scalar multiplication function declaration
 * and structure containing the function pointer and its associated flow protection ID.
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClEcc_ScalarMultFunction_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClEcc_ScalarMultFunction_t)(
    mcuxClSession_Handle_t pSession,                ///< Handle for the current CL session
    mcuxClEcc_CommonDomainParams_t *pDomainParams,  ///< Pointer to ECC domain parameters structure
    uint8_t iScalar,                               ///< Pointer table index of scalar buffer in PKC RAM
    uint32_t scalarBitLength,                      ///< Bit length of the scalar
    uint32_t options                               ///< Parameter to pass options
    ));

typedef struct mcuxClEcc_ScalarMultFunctions
{
    mcuxClEcc_ScalarMultFunction_t secFixScalarMultFct;    ///< Pointer to secure scalar multiplication function that shall be used to perform a scalar multiplication lambda*G for secret scalar lambda in {1,...,n-1} and base point G
    uint32_t secFixScalarMultFctFPId;                     ///< FP ID of the secFixScalarMultFct function
    mcuxClEcc_ScalarMultFunction_t secVarScalarMultFct;    ///< Pointer to secure scalar multiplication function that shall be used to perform a scalar multiplication lambad*P for secret scalar lambda in {1,...,n-1} and arbitrary point P on the curve
    uint32_t secVarScalarMultFctFPId;                     ///< FP ID of the secVarScalarMultFct function
    mcuxClEcc_ScalarMultFunction_t plainFixScalarMultFct;  ///< Pointer to plain scalar multiplication function that shall be used to perform a scalar multiplication lambda*G for non-secret scalar lambda in {1,...,n-1} and base point G
    uint32_t plainFixScalarMultFctFPId;                   ///< FP ID of the plainFixScalarMultFctFPId function
    mcuxClEcc_ScalarMultFunction_t plainVarScalarMultFct;  ///< Pointer to plain scalar multiplication function that shall be used to perform a scalar multiplication lambda*G for non-secret scalar lambda in {1,...,n-1} and arbitrary point P on the curve
    uint32_t plainVarScalarMultFctFPId;                   ///< FP ID of the plainVarScalarMultFct function
} mcuxClEcc_ScalarMultFunctions_t;

/**
 * Common part of domain parameter structure, shared by all ECC functions.
 */
struct mcuxClEcc_CommonDomainParams
{
    uint16_t byteLenP;       ///< byte length of prime p
    uint16_t byteLenN;       ///< byte length of base point order n
    uint8_t *pFullModulusP;  ///< pointer to p'||p (in little endian format)
    uint8_t *pFullModulusN;  ///< pointer to n'||n (in little endian format)
    uint8_t *pR2P;           ///< pointer to Montgomery parameter R^2 mod p (in little endian format)
    uint8_t *pR2N;           ///< pointer to Montgomery parameter R^2 mod n (in little endian format)
    uint8_t *pCurveParam1;   ///< Pointer to first curve parameter (a for Weierstrass and twisted Edwards curves and A for Montgomery curves)
    uint8_t *pCurveParam2;   ///< Pointer to second curve parameter (b for Weierstrass curves, d for twisted Edwards curves and B for Montgomery curves)
    uint8_t *pGx;            ///< Pointer to x-coordinate Gx of base point G
    uint8_t *pGy;            ///< Pointer to y-coordinate Gy of base point G
    uint8_t *pPrecPoints;    ///< Pointer to pre-computed points for fixed base point scalar multiplication (2^(byteLenN * 4) * G for Weierstrass curves, used in ECDSA signature verification; reserved for other curves)
    uint8_t *pLadderConst;   ///< Pointer to pre-computed Montgomery ladder constant (in little endian format, used for Montgomery and Twisted Edwards curves)
    const mcuxClEcc_ScalarMultFunctions_t *pScalarMultFunctions;  ///< Pointer to struct that contains scalar multiplication function pointers
};


/**********************************************************/
/*                                                        */
/* Miscellanious definitions                              */
/*                                                        */
/**********************************************************/

/**
 * Options for internal scalar multiplication functions to determine
 *   - whether scalar multiplication input/output are in affine or projective format.
 *   - whether the output coordinates shall be validated
 */
#define MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_INPUT        (0x000000A5u)
#define MCUXCLECC_SCALARMULT_OPTION_AFFINE_INPUT            (0x0000005Au)
#define MCUXCLECC_SCALARMULT_OPTION_INPUT_MASK              (MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_INPUT | MCUXCLECC_SCALARMULT_OPTION_AFFINE_INPUT)
#define MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_OUTPUT       (0x0000C300u)
#define MCUXCLECC_SCALARMULT_OPTION_AFFINE_OUTPUT           (0x00003C00u)
#define MCUXCLECC_SCALARMULT_OPTION_OUTPUT_MASK             (MCUXCLECC_SCALARMULT_OPTION_PROJECTIVE_OUTPUT | MCUXCLECC_SCALARMULT_OPTION_AFFINE_OUTPUT)
#define MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION       (0x00C30000u)
#define MCUXCLECC_SCALARMULT_OPTION_NO_OUTPUT_VALIDATION    (0x003C0000u)
#define MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION_MASK  (MCUXCLECC_SCALARMULT_OPTION_OUTPUT_VALIDATION | MCUXCLECC_SCALARMULT_OPTION_NO_OUTPUT_VALIDATION)
#define MCUXCLECC_SCALARMULT_OPTION_SECURE                  (0xC3000000u)
#define MCUXCLECC_SCALARMULT_OPTION_PLAIN                   (0x3C000000u)
#define MCUXCLECC_SCALARMULT_OPTION_SECURE_MASK             (MCUXCLECC_SCALARMULT_OPTION_SECURE | MCUXCLECC_SCALARMULT_OPTION_PLAIN)

/**
 * Define specifying the size of the multiplicative scalar blinding bit size
 */
#define MCUXCLECC_SCALARBLINDING_BITSIZE (64u)
#define MCUXCLECC_SCALARBLINDING_BYTELEN (MCUXCLECC_SCALARBLINDING_BITSIZE / 8u)


#define MCUXCLECC_ALL_ONES_WORD (0xFFFFFFFFU)
#define MCUXCLECC_RANDOM_WORD   (0xFA18E8BCu)

/**********************************************************/
/*                                                        */
/* Internal function declarations                         */
/*                                                        */
/**********************************************************/

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_InterleaveScalar)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_InterleaveScalar(uint16_t iScalar, uint32_t scalarBitLength, uint32_t numberOfInterleavings);

/** Helper macro to call #mcuxClEcc_InterleaveScalar with flow protection. */
#define MCUXCLECC_FP_INTERLEAVESCALAR(iScalar, bitLenScalar, numberOfInterleavings)  \
    do{ \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_InterleaveScalar(iScalar, bitLenScalar, numberOfInterleavings));  \
    } while (false)


MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_InterleaveTwoScalars)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_InterleaveTwoScalars(uint16_t iScalar0_iScalar1, uint32_t scalarBitLength);

/**
 * @brief Implements low quality random generation and the value of random is [1, modulus-1].
 *
 * This function generates low quality random and the value is in range [1, modulus-1]
 *
 * @param[in] pSession          Handle for the current CL session
 * @param[in] iModulus          Index of PKC buffer which contains the modulus
 * @param[in] iDst              Index of PKC buffer which the random mod modulus will be written to
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_GenerateRandomModModulus)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_GenerateRandomModModulus(
    mcuxClSession_Handle_t pSession,
    uint8_t iModulus,
    uint8_t iDst
);

#if defined(MCUXCLECC_FEATURE_INTERNAL_GENMULTBLINDING)
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_GenerateMultiplicativeBlinding)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_GenerateMultiplicativeBlinding(
    mcuxClSession_Handle_t pSession,
    uint32_t scalarSize
    );
#endif /* defined(MCUXCLECC_FEATURE_INTERNAL_GENMULTBLINDING) */


MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_BlindedFixScalarMult)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_BlindedFixScalarMult(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_CommonDomainParams_t *pCommonDomainParams,
    uint32_t scalarLength
    );



MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_BlindedVarScalarMult)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_BlindedVarScalarMult(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_CommonDomainParams_t *pCommonDomainParams
    );



MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_SetupEnvironment)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_SetupEnvironment(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_CommonDomainParams_t *pCommonDomainParams,
    uint8_t noOfBuffers
    );

#if defined(MCUXCLECC_FEATURE_INTERNAL_WEIER_INTEGRITYCHECK_PN)
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_IntegrityCheckPN)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_IntegrityCheckPN(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_CommonDomainParams_t *pCommonDomainParams
    );
#endif /* defined(MCUXCLECC_FEATURE_INTERNAL_WEIER_INTEGRITYCHECK_PN) */

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_RecodeAndReorderScalar)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_RecodeAndReorderScalar(
    mcuxClSession_Handle_t pSession,
    uint8_t scalarIndex,
    uint8_t f,
    uint32_t scalarBitLength
    );

/** Helper macro to call #mcuxClEcc_RecodeAndReorderScalar with flow protection. */
#define MCUXCLECC_FP_RECODEANDREORDERSCALAR(scalarIndex, f, scalarBitLength)  \
    do{ \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_RecodeAndReorderScalar(pSession, scalarIndex, f, scalarBitLength));  \
    } while (false)


MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_SecurePointSelectML)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_SecurePointSelectML(
    uint32_t maskedCurrentScalarWord,               ///<  [in]  maskedCurrentScalarWord       Currently processed masked scalar word
    uint32_t currentScalarWordMask,                 ///<  [in]  currentScalarWordMask         Mask of currently processed scalar word
    uint32_t currentScalarBitInWord,                ///<  [in]  currentScalarBitInWord        Position of currently processed bit
    uint8_t iAccLadderCoords,                       ///<  [in]  iAccLadderCoords              Pointer table index of accumulated ladder coordinates
    uint8_t iVirtualCoords                          ///<  [out] iVirtualCoords                Pointer table index of virtual points, which will point to coordinates of accumulated ladder point
);

/**
 * Declaration of the secure point table entry selection function
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_SecurePtrTableEntrySelect)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_SecurePtrTableEntrySelect(
    const uint8_t *pTable,
    uint32_t scalarWord0,
    uint32_t scalarWord1,
    uint32_t scalarDigitOffset,
    uint32_t tableEntrySizeLog2,
    uint32_t tableEntryIndexBitSize,
    uint8_t *pShufBuffer,
    uint8_t *pShufBuffer2,
    uint8_t *pTargetTableEntry,
    const uint8_t *pPrecPointTableMask
);


/**
 * Declaration of function to cast pointer to specific workarea type
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_castToEccCpuWorkArea)
static inline mcuxClEcc_CpuWa_t* mcuxClEcc_castToEccCpuWorkArea(uint32_t* pWa)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClEcc_CpuWa_t *) pWa;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_INTERNAL_H_ */
