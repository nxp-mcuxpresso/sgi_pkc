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
 * @file  mcuxClEcc_Internal_Random.c
 * @brief mcuxClEcc: implementation of ECC function mcuxClEcc_GenerateRandomModModulus
 */


#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClRandom.h>
#include <mcuxClEcc.h>

#include <internal/mcuxClPkc_Internal.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_FUP.h>

#include <internal/mcuxClSession_Internal_EntryExit.h>

/**
 * This function generates low quality random and the value is in range [1, modulus-1].
 *
 * Inputs:
 *   - pSession         Handle for the current CL session
 *   - iModulus         Index of PKC buffer which contains the modulus
 *   - iDst             Index of PKC buffer which the random mod modulus will be written to
 *
 * Prerequisites: N/A.
 *
 * Result in PKC workarea:
 *   buffer iDst which the random mod modulus will be written to.
 *
 * Other modifications:
 *   buffers T0, T1, T2, V0, V1 are modified (as temp);
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_GenerateRandomModModulus)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_GenerateRandomModModulus(
    mcuxClSession_Handle_t pSession,
    uint8_t iModulus,
    uint8_t iDst
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_GenerateRandomModModulus);

    /* Determine pointer table pointer */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    MCUXCLPKC_WAITFORFINISH();
    pOperands[ECC_V0] = (uint16_t) pOperands[iModulus];
    pOperands[ECC_V1] = (uint16_t) pOperands[iDst];

    MCUXCLBUFFER_INIT(buffRandom, NULL, MCUXCLPKC_OFFSET2PTR(pOperands[ECC_T0]), operandSize);
    MCUX_CSSL_FP_FUNCTION_CALL(ret_Prng_GetRandom, mcuxClRandom_ncGenerate(pSession, buffRandom, operandSize));
    if (MCUXCLRANDOM_STATUS_OK != ret_Prng_GetRandom)
    {
        MCUXCLSESSION_ERROR(pSession, MCUXCLECC_STATUS_RNG_ERROR);
    }

    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_ReduceRandomModModulus, mcuxClEcc_FUP_ReduceRandomModModulus_LEN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_GenerateRandomModModulus, MCUXCLECC_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
}
