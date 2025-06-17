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
 * @file  mcuxClEcc_ECDSA_Internal_PrepareMessageDigest.c
 * @brief Function to import and pad or truncate the ECDSA message digest
 */


#include <mcuxCsslAnalysis.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClMath_Internal_Utils.h>

#include <internal/mcuxClEcc_ECDSA_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal.h>




/**
 * This function imports a message digest to PKC and prepares it for usage within ECDSA
 * by truncating it or padding it with zeros as specified in FIPS 186-5.
 *
 * Input:
 *  - pIn          Pointer to message digest
 *  - inSize       Byte length of message digest
 *  - byteLenN     Byte length of base point order n
 *
 * Prerequisites:
 *  - ps1Len = (operandSize, operandSize)
 *  - Buffer ECC_NFULL contains n'||n
 *
 * Result:
 *  - If no errors are encountered, the prepared message digest is stored in ECC_S2.
 *
 * @attention The PKC calculation might be still on-going, call #MCUXCLPKC_WAITFORFINISH before CPU accesses to the result.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_ECDSA_PrepareMessageDigest)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_ECDSA_PrepareMessageDigest(
    mcuxCl_InputBuffer_t pIn,
    uint32_t inSize,
    uint32_t byteLenN
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_ECDSA_PrepareMessageDigest);

    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(
        byteLenN,
        MCUXCLECC_WEIERECC_MIN_SIZE_BASEPOINTORDER,
        MCUXCLECC_WEIERECC_MAX_SIZE_BASEPOINTORDER);

    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();

    /* Import message hash (up to byteLenN bytes). */
    uint32_t byteLenHashImport = MCUXCLCORE_MIN(inSize, byteLenN);
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(mcuxClEcc_ECDSA_PrepareMessageDigest, ECC_S2, pIn, byteLenHashImport, operandSize);

    /* Truncate message hash if its bit length is longer than that of n. */
    if (inSize >= byteLenN)
    {
        /* Count leading zeros in MSByte of n. */
        const volatile uint8_t * ptrN = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_N]);
        uint8_t nMSByte = ptrN[byteLenN - 1u];
        uint32_t nMSByte_LeadZeros = (uint32_t) mcuxClMath_CountLeadingZerosWord((uint32_t) nMSByte) - (8u * ((sizeof(uint32_t)) - 1u));

        /* Only keep the first bitLenN bits of hash. */
        MCUXCLPKC_FP_CALC_OP1_SHR(ECC_S2, ECC_S2, (uint8_t) (nMSByte_LeadZeros & 0xFFu));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_ECDSA_PrepareMessageDigest,
        MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER,
        MCUX_CSSL_FP_CONDITIONAL((inSize >= byteLenN), MCUXCLPKC_FP_CALLED_CALC_OP1_SHR));
}
