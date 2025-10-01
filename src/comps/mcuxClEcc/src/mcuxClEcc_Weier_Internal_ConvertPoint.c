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
 * @file  mcuxClEcc_Weier_Internal_ConvertPoint.c
 * @brief Weierstrass curve internal point conversion
 */


#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal.h>

#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal_FUP.h>
#include <internal/mcuxClPrng_Internal_Functions.h>

/**
 * This function securely converts a point from Jacobian to affine coordinates.
 *
 * Inputs in PKC workarea:
 *   buffers (X0,Y0,Z) contain the point, Jacobian, Montgomery representation.
 *
 * Result in PKC workarea:
 *   buffer (XA,YA), contain the point, affine, normal representation.
 *
 * @attention The PKC calculation might be still on-going, call #MCUXCLPKC_WAITFORFINISH before CPU accesses to the result.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_Weier_SecureConvertPoint_JacToAffine)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_Weier_SecureConvertPoint_JacToAffine(void)

{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_Weier_SecureConvertPoint_JacToAffine);

    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    const uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();

    /* T0 = ModInv(Z), where Z = (z * 256^LEN) \equiv z in MR. */
    MCUXCLMATH_FP_MODINV(ECC_T0, WEIER_Z, ECC_P, ECC_T1);
    /* T0 = z^(-1) * 256^(-LEN) \equiv z^(-1) * 256^(-2LEN) in MR. */

    uint8_t * const ptrRnd = MCUXCLPKC_OFFSET2PTR(pOperands[WEIER_YA]);
    MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(ptrRnd, operandSize));

    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_Weier_SecureConvertPoint_JacToAffine,
                        mcuxClEcc_FUP_Weier_SecureConvertPoint_JacToAffine_LEN);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClEcc_Weier_SecureConvertPoint_JacToAffine,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
}
