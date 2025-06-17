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
 * @file  mcuxClEcc_Weier_Internal_FP.h
 * @brief flow protection definitions
 */


#ifndef MCUXCLECC_WEIER_INTERNAL_FP_H_
#define MCUXCLECC_WEIER_INTERNAL_FP_H_

#include <mcuxClCore_Platform.h>


/**********************************************************/
/* mcuxClEcc_WeierECC_GenerateKeyPair                      */
/**********************************************************/

/* Initialization */
#define MCUXCLECC_FP_GENERATEKEYPAIR_INIT  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_SetupEnvironment),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_RandomizeUPTRT),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_QSquared)

/* Import/check base point */
#define MCUXCLECC_FP_GENERATEKEYPAIR_BASE_POINT  \
    MCUXCLECC_FP_GENERATEKEYPAIR_INIT,  \
    MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER,  \
    MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointCheckAffineNR)

/* Generate private key */
#define MCUXCLECC_FP_GENERATEKEYPAIR_GENERATE_PRIKEY  \
    MCUXCLECC_FP_GENERATEKEYPAIR_BASE_POINT,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Int_CoreKeyGen)

/* Calculate public key */
#define MCUXCLECC_FP_GENERATEKEYPAIR_CALC_PUBKEY  \
    MCUXCLECC_FP_GENERATEKEYPAIR_GENERATE_PRIKEY,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),  \
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM,  \
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM,  \
    MCUXCLPKC_FP_CALLED_CALC_OP1_NEG,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_SecurePointMult),  \
    MCUXCLPKC_FP_CALLED_CALC_OP1_LSB0s,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_SecurePointMult)

/* Convert/check public key */
#define MCUXCLECC_FP_GENERATEKEYPAIR_CONVERT_PUBKEY  \
    MCUXCLECC_FP_GENERATEKEYPAIR_CALC_PUBKEY,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointCheckAffineNR)

/* Check n/p and export */
#define MCUXCLECC_FP_GENERATEKEYPAIR_FINAL  \
    MCUXCLECC_FP_GENERATEKEYPAIR_CONVERT_PUBKEY,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_IntegrityCheckPN),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_linkKeyPair)


/**********************************************************/
/* mcuxClEcc_ECDSA_GenerateSignature                       */
/**********************************************************/

/* Initialization */
#define MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_INIT  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_SetupEnvironment)

#define MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_BEFORE_LOOP  \
    MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_INIT, \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_RandomizeUPTRT)

/* Mail loop - first part, until checking r */
#define MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_LOOP_R_0  \
    MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER,  \
    MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointCheckAffineNR)

#define MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_LOOP_R_1  \
    MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_LOOP_R_0,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Int_CoreKeyGen)

#define MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_LOOP_R  \
    MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_LOOP_R_1,  \
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM,  \
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM,  \
    MCUXCLPKC_FP_CALLED_CALC_OP1_NEG,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_SecurePointMult),  \
    MCUXCLPKC_FP_CALLED_CALC_OP1_LSB0s,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_SecurePointMult),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointCheckAffineNR),  \
    MCUXCLPKC_FP_CALLED_CALC_MC1_MS

/* Mail loop - second part, checking s */
#define MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_LOOP_S  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate_Internal),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ECDSA_PrepareMessageDigest),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv),  \
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM,  \
    MCUXCLPKC_FP_CALLED_CALC_MC1_MS

#define MCUXCLECC_FP_ECDSA_GENERATESIGNATURE_FINAL  \
   	MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_IntegrityCheckPN),  \
    MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFER,  \
    MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFEROFFSET,  \
    MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,  \
    MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE


/**********************************************************/
/* mcuxClEcc_ECDH_KeyAgreement                             */
/**********************************************************/

/* Initialization */
#define MCUXCLECC_FP_ECDH_KEYAGREEMENT_INIT  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_SetupEnvironment),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_RandomizeUPTRT)

/* Import/check base point */
#define MCUXCLECC_FP_ECDH_KEYAGREEMENT_BASE_POINT  \
    MCUXCLECC_FP_ECDH_KEYAGREEMENT_INIT,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointCheckAffineNR)

/* Import scalar */
#define MCUXCLECC_FP_ECDH_KEYAGREEMENT_SCALAR  \
    MCUXCLECC_FP_ECDH_KEYAGREEMENT_BASE_POINT, \
	MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_BlindedVarScalarMult)

/* Calculate scalar multiplication */
#define MCUXCLECC_FP_ECDH_KEYAGREEMENT_SCALAR_MULTIPLICATION  \
    MCUXCLECC_FP_ECDH_KEYAGREEMENT_SCALAR,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Weier_PointCheckJacMR)

/* Convert/check result of scalar multiplication */
#define MCUXCLECC_FP_ECDH_KEYAGREEMENT_CONVERT_POINT  \
    MCUXCLECC_FP_ECDH_KEYAGREEMENT_SCALAR_MULTIPLICATION,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Weier_SecureConvertPoint_JacToAffine)

/* Check n/p and export */
#define MCUXCLECC_FP_ECDH_KEYAGREEMENT_FINAL  \
    MCUXCLECC_FP_ECDH_KEYAGREEMENT_CONVERT_POINT,  \
	MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_IntegrityCheckPN),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SecureExportBigEndianFromPkc), \
    MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,  \
    MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE


/**********************************************************/
/* mcuxClEcc_ECDSA_VerifySignature                         */
/**********************************************************/

#define MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_INIT  \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_SetupEnvironment), \
        MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER, \
        MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFEROFFSET

#define MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_PREPARE_AND_CHECK \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ECDSA_SignatureRangeCheck), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ECDSA_PrepareMessageDigest),  \
        MCUXCLPKC_FP_CALLED_CALC_MC1_MS, \
        MCUXCLPKC_FP_CALLED_CALC_MC1_MR, \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_InterleaveTwoScalars)

#define MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P1 \
       MCUX_CSSL_FP_CONDITIONAL((MCUXCLPKC_FLAG_ZERO != checkHashZero), \
            pDomainParams->common.pScalarMultFunctions->plainFixScalarMultFctFPId), \
        MCUXCLPKC_FP_CALLED_CALC_OP1_NEG

#define MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P2 \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_load), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointCheckAffineNR), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_RepeatPointDouble), \
        MCUXCLECC_FP_CALLED_CALCFUP_ADD_ONLY, \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Int_PointMult)

#define MCUXCLECC_FP_ECDSA_VERIFYSIGNATURE_CALC_P1_ADD_P2 \
        MCUX_CSSL_FP_CONDITIONAL((MCUXCLPKC_FLAG_ZERO != checkHashZero), \
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointFullAdd)), \
        MCUXCLPKC_FP_CALLED_CALC_MC1_MM, \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointCheckAffineNR), \
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP



/**********************************************************/
/* mcuxClEcc_WeierECC_GenerateDomainParams                 */
/**********************************************************/

#define MCUXCLECC_FP_WEIERECC_GENERATEDOMAINPARAMS_INIT_AND_VERIFY  \
    MCUXCLPKC_FP_CALLED_REQUEST_INITIALIZE, \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_GenerateUPTRT), \
    MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER, \
    MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER, \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_NDash), \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_NDash), \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus), \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus), \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_QSquared), \
    MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER, \
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM, \
    MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER, \
    MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER, \
    MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFEROFFSET, \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Weier_DomainParamsCheck),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_QDash),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup)

#define MCUXCLECC_FP_WEIERECC_GENERATEDOMAINPARAMS_FINAL(options)  \
    MCUXCLECC_FP_WEIERECC_GENERATEDOMAINPARAMS_INIT_AND_VERIFY,  \
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLECC_OPTION_GENERATEPRECPOINT_YES == ((options) & MCUXCLECC_OPTION_GENERATEPRECPOINT_MASK), \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),  \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_RepeatPointDouble),  \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv),  \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup) ),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
    MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER,  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLECC_OPTION_GENERATEPRECPOINT_YES == ((options) & MCUXCLECC_OPTION_GENERATEPRECPOINT_MASK),  \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc),  \
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc) ),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportBigEndianToPkc),  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),  \
    MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,  \
    MCUXCLPKC_FP_CALLED_DEINITIALIZE_RELEASE

#define MCUXCLECC_FP_WEIERECC_DOMAINPARAMSCHECK_INTERMEDIATE \
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP, \
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP, \
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP

#define MCUXCLECC_FP_WEIERECC_DOMAINPARAMSCHECK_FINAL \
            MCUXCLECC_FP_WEIERECC_DOMAINPARAMSCHECK_INTERMEDIATE, \
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup), \
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointCheckAffineNR)

#endif /* MCUXCLECC_WEIER_INTERNAL_FP_H_ */
