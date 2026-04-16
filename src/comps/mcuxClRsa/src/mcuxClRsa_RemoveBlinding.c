/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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

/** @file  mcuxClRsa_RemoveBlinding.c
 *  @brief mcuxClRsa: function, which is called to remove modulus blinding
 */

#include <stdint.h>
#include <mcuxClToolchain.h>

#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal_Functions.h>

#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_RemoveBlinding_FUP.h>
#include <internal/mcuxClSession_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_RemoveBlinding)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_RemoveBlinding(
  mcuxClSession_Handle_t pSession,
  uint32_t iR_iX_iNb_iB,
  uint16_t iT2_iT1,
  uint32_t nbPkcByteLength,
  uint32_t bPkcByteLength)
{

  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_RemoveBlinding);

  /* Prepare local UPTRT. */
  const uint32_t uptrtSizeWord = MCUXCLRSA_INTERNAL_REMOVEBLINDING_UPTRT_BYTESIZE / sizeof(uint32_t);
  MCUX_CSSL_FP_FUNCTION_CALL(uint16_t*, pOperands, mcuxClSession_allocateWords_uptrt(pSession, uptrtSizeWord));

  const uint16_t *pBackupPtrUptrt;
  /* mcuxClMath_InitLocalUptrt always returns _OK. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMath_InitLocalUptrt(iR_iX_iNb_iB, (uint32_t) iT2_iT1, pOperands, 6U, &pBackupPtrUptrt));
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_REMOVEBLINDING_ZERO] = 0x0U;

  /* Call the FUP program to convert result of the exponentiation to normal representation modulo Nb */
  MCUXCLPKC_FP_CALCFUP(mcuxClRsa_RemoveBlinding_FUP,
    mcuxClRsa_RemoveBlinding_FUP_LEN);

  /* Calculate R=T1/b */
  MCUXCLMATH_FP_EXACTDIVIDEODD(
    pSession,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_REMOVEBLINDING_R,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_REMOVEBLINDING_T1,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_REMOVEBLINDING_B,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_REMOVEBLINDING_T2,
    nbPkcByteLength,
    bPkcByteLength);

  /* Restore pUptrt. */
  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_SETUPTRT(pBackupPtrUptrt);

  mcuxClSession_freeWords_uptrt(pSession, uptrtSizeWord);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_RemoveBlinding,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_uptrt),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_InitLocalUptrt),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ExactDivideOdd)
  );
}
