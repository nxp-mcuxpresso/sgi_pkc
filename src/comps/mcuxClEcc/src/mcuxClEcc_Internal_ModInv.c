/*--------------------------------------------------------------------------*/
/* Copyright 2024-2026 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/** @file  mcuxClEcc_ModInv.c
 *  @brief mcuxClEcc: function, which is called to compute modular inversion X^(-1) mod N in a blinded way
 */

#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Platform.h>

#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_FUP.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPrng_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_ModInv)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClEcc_ModInv(mcuxClSession_Handle_t pSession, uint32_t iR_iX_iN_iT, uint32_t iRnd)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_ModInv);

  uint16_t* pOperands = MCUXCLPKC_GETUPTRT();
  uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
  uint32_t iR = (iR_iX_iN_iT >> 24u) & 0xFFu;
  uint32_t iX = (iR_iX_iN_iT >> 16u) & 0xFFu;
  uint32_t iN = (iR_iX_iN_iT >> 8u) & 0xFFu;
  uint32_t iT = (iR_iX_iN_iT) & 0xFFu;

  /* Generate random number (to blind the X). */
  uint8_t* const pRnd = MCUXCLPKC_OFFSET2PTR(pOperands[iRnd]);
  MCUXCLPKC_WAITFORFINISH();

  /* Make sure the rnd%n != 0 */
  MCUX_CSSL_FP_COUNTER_STMT(uint32_t loopIter = 0U);
  while(true)
  {
    MCUX_CSSL_FP_COUNTER_STMT(loopIter++);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(pRnd, operandSize));
    MCUXCLPKC_FP_CALC_MC1_MR(iT, iRnd, iN);
    MCUXCLPKC_FP_CALC_MC1_MS(iR, iT, iN, iN);
    if(MCUXCLPKC_FLAG_NONZERO == MCUXCLPKC_WAITFORFINISH_GETZERO())
    {
      break;
    }
  }

  /* Blinding the X */
  MCUXCLPKC_FP_CALC_MC1_MM(iT, iX, iRnd, iN);
  MCUXCLPKC_FP_CALC_MC1_MS(iX, iT, iN, iN);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMath_ModInv(pSession, iR_iX_iN_iT, MCUXCLMATH_XN_COPRIME));

  /* Unblinding the X^(-1) */
  MCUXCLPKC_FP_CALC_MC1_MM(iT, iR, iRnd, iN);
  MCUXCLPKC_FP_CALC_MC1_MS(iR, iT, iN, iN);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(
    mcuxClEcc_ModInv,
    loopIter * (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal) + MCUXCLPKC_FP_CALLED_CALC_MC1_MR +
                MCUXCLPKC_FP_CALLED_CALC_MC1_MS),
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM,
    MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM,
    MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv)
  );
}
