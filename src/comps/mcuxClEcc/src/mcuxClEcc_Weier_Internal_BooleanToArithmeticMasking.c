/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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
 * @file  mcuxClEcc_Weier_BooleanToArithmeticMasking.c
 * @brief Function for converting boolean mask to arithmetic mask
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxClEcc.h>

#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClEcc_Weier_Internal_PkcWaLayout.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>
#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClPrng_Internal_Functions.h>

 /**
 * Function for converting from boolean to arithmetic masking.
 *
 * PS2 Oplen need to be set at least to length of the expected arithmetic masking
 * Masked value will be updated with new value.
 * Input and temporary buffers are considered double-sized thererfore buffers ECC_Sx are used instead of ECC_Tx
 *
 * @retval #MCUXCLECC_STATUS_OK
 * @retval #MCUXCLECC_STATUS_RNG_ERROR
 * @retval #MCUXCLECC_STATUS_FAULT_ATTACK
 *
 * Inputs in PKC workarea:
 *   S2 - Boolean Masked value
 *   S3 - Mask
 *
 * Results in PKC workarea:
 *   S2 - Arithmetic masked value
 * Other modifications:
 *   buffers S0 and S1 (as temp) are modified
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_Weier_BooleanToArithmeticMasking)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_Weier_BooleanToArithmeticMasking(void)

{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_Weier_BooleanToArithmeticMasking);

    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    const uint32_t operandSize = MCUXCLPKC_PS2_GETOPLEN();


    uint8_t * const ptrRnd = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S1]);
    MCUXCLPKC_WAITFORFINISH();
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(ptrRnd, operandSize));

    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_Weier_BooleanToArithmeticMasking,
                        mcuxClEcc_FUP_Weier_BooleanToArithmeticMasking_LEN);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_Weier_BooleanToArithmeticMasking,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
}
