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
 * @file  mcuxClEcc_Internal_IntegrityCheckPN.c
 * @brief mcuxClEcc: implementation of integrity check for p and n
 */


#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClMath_Internal_Functions.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>

#include <internal/mcuxClEcc_Internal.h>

#include <internal/mcuxClSession_Internal.h>

/**
 * This function check integrity of base point order n, and modulus p, and their shifted counterparts
 *
 * Prerequisites:
 * Buffer ECC_P contains the modulus p
 * Buffer ECC_PS contains the shifted modulus associated to p
 * Buffer ECC_N contains the base point order n
 * Buffer ECC_NS contains the shifted base point order associated to n
 *
 * Input:
 * @param[in]     pCommonDomainParams       Pointer to domain parameter struct passed via API

 * @return status
 * @retval #MCUXCLECC_STATUS_OK              if integrity check passes.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_IntegrityCheckPN)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_IntegrityCheckPN(mcuxClSession_Handle_t pSession, mcuxClEcc_CommonDomainParams_t *pCommonDomainParams)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_IntegrityCheckPN);

    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    const uint32_t byteLenP = (uint32_t) pCommonDomainParams->byteLenP;
    const uint32_t byteLenN = (uint32_t) pCommonDomainParams->byteLenN;

    /* Import prime p and order n again. */
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(ECC_T0, &(pCommonDomainParams->pFullModulusP[MCUXCLPKC_WORDSIZE]), byteLenP, operandSize);
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(ECC_T1, &(pCommonDomainParams->pFullModulusN[MCUXCLPKC_WORDSIZE]), byteLenN, operandSize);

    /* Re-calculate shifted prime p and shifted order N */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus));
    MCUXCLMATH_FP_SHIFTMODULUS(ECC_T2, ECC_T0);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus));
    MCUXCLMATH_FP_SHIFTMODULUS(ECC_T3, ECC_T1);

    /* Compare re-imported with existing values for p and n. */
    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_T0, ECC_P);
    uint32_t zeroFlag_checkP = MCUXCLPKC_WAITFORFINISH_GETZERO();
    MCUX_CSSL_DI_RECORD(sigValiditycheckP, (uint32_t)zeroFlag_checkP);

    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_T1, ECC_N);
    uint32_t zeroFlag_checkN = MCUXCLPKC_WAITFORFINISH_GETZERO();
    MCUX_CSSL_DI_RECORD(sigValiditycheckN, (uint32_t)zeroFlag_checkN);

    /* Compare re-imported with existing values for shifted p and shifted n. */
    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_T2, ECC_PS);
    uint32_t zeroFlag_checkShiftedP = MCUXCLPKC_WAITFORFINISH_GETZERO();
    MCUX_CSSL_DI_RECORD(sigValiditycheckShiftedP, (uint32_t)zeroFlag_checkShiftedP);

    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_T3, ECC_NS);
    uint32_t zeroFlag_checkShiftedN = MCUXCLPKC_WAITFORFINISH_GETZERO();
    MCUX_CSSL_DI_RECORD(sigValiditycheckShiftedN, (uint32_t)zeroFlag_checkShiftedN);

    /* Return FAULT_ATTACK if a check failed. */
    if ((MCUXCLPKC_FLAG_ZERO != zeroFlag_checkP)
        || (MCUXCLPKC_FLAG_ZERO != zeroFlag_checkN) || (MCUXCLPKC_FLAG_ZERO != zeroFlag_checkShiftedP) || (MCUXCLPKC_FLAG_ZERO != zeroFlag_checkShiftedN))
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    MCUX_CSSL_DI_EXPUNGE(sigValiditycheckN, MCUXCLPKC_FLAG_ZERO);
    MCUX_CSSL_DI_EXPUNGE(sigValiditycheckP, MCUXCLPKC_FLAG_ZERO);
    MCUX_CSSL_DI_EXPUNGE(sigValiditycheckShiftedN, MCUXCLPKC_FLAG_ZERO);
    MCUX_CSSL_DI_EXPUNGE(sigValiditycheckShiftedP, MCUXCLPKC_FLAG_ZERO);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_IntegrityCheckPN,
        MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER,
        MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP);
}
