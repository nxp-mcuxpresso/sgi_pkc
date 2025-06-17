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
 * @file  mcuxClEcc_Weier_Internal.h
 * @brief internal header for short Weierstrass curves
 */


#ifndef MCUXCLECC_WEIER_INTERNAL_H_
#define MCUXCLECC_WEIER_INTERNAL_H_


#include <mcuxClCore_Platform.h>
#include <mcuxClMemory.h>
#include <mcuxClKey_Types.h>
#include <mcuxClMac.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClEcc_Types.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal_PkcWaLayout.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Domain parameter structure for ECC functions based on Weierstrass functions.
 */
struct mcuxClEcc_Weier_DomainParams
{
    mcuxClEcc_CommonDomainParams_t common;  ///< structure containing pointers and lengths for common ECC parameters (see Common ECC Domain parameters)
};

/**
 * @brief Common scalar multiplication functions for Weierstrass curves
*/
extern const mcuxClEcc_ScalarMultFunctions_t mcuxClEcc_Weier_ScalarMultFunctions;


/**********************************************************/
/* Helper macros of import/export with flow protection    */
/**********************************************************/

/** Helper macro to call #mcuxClMemory_copy for importing data to PKC workarea with flow protection. */
#define MCUXCLECC_FP_IMPORT_TO_PKC_BUFFER(pOffsetTable, iTarget, pSource, byteLen)  \
    MCUXCLECC_FP_MEMORY_COPY(MCUXCLPKC_OFFSET2PTR((pOffsetTable)[iTarget]), pSource, byteLen)

#define MCUXCLECC_FP_CALLED_MEMORY_COPY  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
#define MCUXCLECC_FP_CALLED_IMPORT_TO_PKC_BUFFER  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)


/**********************************************************/
/* Macros for custom domain parameter generation          */
/**********************************************************/

#define MCUXCLECC_CUSTOMPARAMS_OFFSET_PFULL                   (0u)
#define MCUXCLECC_CUSTOMPARAMS_OFFSET_NFULL(byteLenP)         ((byteLenP) + MCUXCLPKC_WORDSIZE)
#define MCUXCLECC_CUSTOMPARAMS_OFFSET_R2P(byteLenP, byteLenN) (MCUXCLECC_CUSTOMPARAMS_OFFSET_NFULL(byteLenP) + (byteLenN) + MCUXCLPKC_WORDSIZE)
#define MCUXCLECC_CUSTOMPARAMS_OFFSET_R2N(byteLenP, byteLenN) (MCUXCLECC_CUSTOMPARAMS_OFFSET_R2P(byteLenP, byteLenN) + (byteLenP))
#define MCUXCLECC_CUSTOMPARAMS_OFFSET_CP1(byteLenP, byteLenN) (MCUXCLECC_CUSTOMPARAMS_OFFSET_R2N(byteLenP, byteLenN) + (byteLenN))
#define MCUXCLECC_CUSTOMPARAMS_OFFSET_CP2(byteLenP, byteLenN) (MCUXCLECC_CUSTOMPARAMS_OFFSET_CP1(byteLenP, byteLenN) + (byteLenP))
#define MCUXCLECC_CUSTOMPARAMS_OFFSET_GX(byteLenP, byteLenN)  (MCUXCLECC_CUSTOMPARAMS_OFFSET_CP2(byteLenP, byteLenN) + (byteLenP))
#define MCUXCLECC_CUSTOMPARAMS_OFFSET_GY(byteLenP, byteLenN)  (MCUXCLECC_CUSTOMPARAMS_OFFSET_GX(byteLenP, byteLenN) + (byteLenP))
#define MCUXCLECC_CUSTOMPARAMS_OFFSET_PP(byteLenP, byteLenN)  (MCUXCLECC_CUSTOMPARAMS_OFFSET_GY(byteLenP, byteLenN) + (byteLenP))

#define MCUXCLECC_CUSTOMPARAMS_SIZE_FIXED (sizeof(mcuxClEcc_Weier_DomainParams_t) + 2u * MCUXCLPKC_WORDSIZE)
#define MCUXCLECC_CUSTOMPARAMS_SIZE_NO_OF_PLEN (8u /* PFULL, R2P, CP1, CP2, GX, GY, PP */)
#define MCUXCLECC_CUSTOMPARAMS_SIZE_NO_OF_NLEN (2u /* NFULL, R2N */)



/**********************************************************/
/* Internal function declaration - Setup Environment      */
/**********************************************************/

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_WeierECC_SetupEnvironment)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_WeierECC_SetupEnvironment(
        mcuxClSession_Handle_t pSession,
        mcuxClEcc_Weier_DomainParams_t *pWeierDomainParams,
        uint8_t noOfBuffers
        );

/**********************************************************/
/* Internal function declaration - point/params checks    */
/**********************************************************/
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_PointCheckAffineNR)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_PointCheckAffineNR(mcuxClSession_Handle_t pSession);


MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_Weier_PointCheckJacMR)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_Weier_PointCheckJacMR(mcuxClSession_Handle_t pSession);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_Weier_SecureConvertPoint_JacToAffine)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_Weier_SecureConvertPoint_JacToAffine(void);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_Weier_DomainParamsCheck)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_Weier_DomainParamsCheck(mcuxClSession_Handle_t pSession,
                                                                               const uint32_t byteLenP,
                                                                               const uint32_t byteLenN);

/**********************************************************/
/* Internal function declaration - point arithmetic       */
/**********************************************************/
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_RepeatPointDouble)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_RepeatPointDouble(uint32_t iteration);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_PointFullAdd)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_PointFullAdd(void);


/**********************************************************/
/* Internal function declaration - point multiplication   */
/**********************************************************/
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_Int_PointMult)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_Int_PointMult(uint8_t iScalar, uint32_t scalarBitLength);

/**
 * Declaration of function to perform plain (not protected against side-channel attacks) scalar multiplication with the base point on Weierstrass curves
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_Weier_PlainFixScalarMult, mcuxClEcc_ScalarMultFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_Weier_PlainFixScalarMult(
    mcuxClSession_Handle_t pSession,                 ///<  [in]  pSession            Handle for the current CL session
    mcuxClEcc_CommonDomainParams_t *pDomainParams,   ///<  [in]  pDomainParams       Pointer to ECC common domain parameters structure
    uint8_t iScalar,                                ///<  [in]  iScalar             Pointer table index of scalar
    uint32_t scalarBitLength,                       ///<  [in]  scalarBitLength     Bit length of the scalar
    uint32_t options                                ///<  [in]  options             Parameter to pass options
);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_SecurePointMult)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_SecurePointMult(uint8_t iScalar,
                                                                       uint32_t scalarBitLength);

/**********************************************************/
/* Internal function declaration - key generation         */
/**********************************************************/

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_Weier_BooleanToArithmeticMasking)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_Weier_BooleanToArithmeticMasking(void);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_Int_CoreKeyGen)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_Int_CoreKeyGen(mcuxClSession_Handle_t pSession,
                                                                      uint32_t nByteLength);



/**********************************************************/
/* Internal declarations - Point Decoding                 */
/**********************************************************/

/**
 * Declaration of Weierstrass point decoding function
 * and structure containing the function pointer and its associated flow protection ID.
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClEcc_WeierECC_PointDecodingFunction_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) (*mcuxClEcc_WeierECC_PointDecodingFunction_t)(
    mcuxClSession_Handle_t pSession,                         ///<        pSession               Handle for the current CL session
    mcuxCl_InputBuffer_t pEncodedPoint,                      ///<  [in]  pEncodedPoint          Buffer with encoded point
    mcuxCl_Buffer_t pDecodedPoint,                           ///<  [out] pDecodedPoint          Pointer to decoded point
    mcuxClEcc_WeierECC_PointEncType_t pointEncType,          ///<  [in]  pointEncType           Point encoding type specifying all information needed about the applied point encoding format
    mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams    ///<  [in]  pEccWeierDomainParams  Pointer to Weierstrass domain parameters
));


MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_WeierECC_PointDecFct_SEC, mcuxClEcc_WeierECC_PointDecodingFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_WeierECC_PointDecFct_SEC(mcuxClSession_Handle_t pSession,
                                                                                mcuxCl_InputBuffer_t pEncodedPoint,
                                                                                mcuxCl_Buffer_t pDecodedPoint,
                                                                                mcuxClEcc_WeierECC_PointEncType_t pointEncType,
                                                                                mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams);
/**
 * Weierstrass point encoding variant descriptor structure
 */
struct mcuxClEcc_WeierECC_PointEncDescriptor
{
    mcuxClEcc_WeierECC_PointDecodingFunction_t pointDecFct; ///< Weierstrass point decoding function
    uint32_t pointDecFctFPId;                              ///< FP ID of the function pointDecFct
};


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_WEIER_INTERNAL_H_ */
