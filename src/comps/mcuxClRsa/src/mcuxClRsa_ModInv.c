/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023-2025 NXP                                            */
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

/** @file  mcuxClRsa_ModInv.c
 *  @brief mcuxClRsa: function, which is called to compute modular inversion X^(-1) mod N in a blinded way
 *
 *  The implementation assumes that:
 *  - N is congruent 2 mod 4
 *  - size of Rnd = MCUXCLRSA_PKC_WORDSIZE
 *  - Nb = N * Rnd
 *  - lenX <= lenNb - MCUXCLRSA_PKC_WORDSIZE
 *  - content of X and Nb will be destroyed
 */

#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>

#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClMath_Internal_Functions.h>
#include <internal/mcuxClSession_Internal.h>

#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>
#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_ModInv_FUP.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_ModInv)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_ModInv(uint32_t iR_iX_iNb_iRnd, uint32_t iT1_iT0, uint32_t lenX, uint32_t lenNb)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_ModInv);

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(lenNb, MCUXCLRSA_MIN_MODLEN + MCUXCLRSA_PKC_WORDSIZE, MCUXCLRSA_MAX_MODLEN + MCUXCLRSA_PKC_WORDSIZE, /* void */)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(lenX, MCUXCLRSA_PKC_WORDSIZE, lenNb - MCUXCLRSA_PKC_WORDSIZE, /* void */)

  /* Prepare local UPTRT. */
  uint16_t pOperands[MCUXCLRSA_INTERNAL_MODINV_UPTRT_SIZE];
  const uint16_t *backupPtrUptrt;

  /* Mapping to internal indices:                         R  X  Nb  RND   NB_ODD_SHIFT NB_ODD */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMath_InitLocalUptrt(iR_iX_iNb_iRnd, iT1_iT0, pOperands, 6u, &backupPtrUptrt));

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Caller shall provide the buffer for Ndsah.")
  pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD] += MCUXCLRSA_PKC_WORDSIZE; /* offset for Ndsah */
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  /* Backup Ps1 and Ps2 length, restore them when returning */
  uint32_t bakPs1LenReg = MCUXCLPKC_PS1_GETLENGTH_REG();
  uint32_t bakPs2LenReg = MCUXCLPKC_PS2_GETLENGTH_REG();

  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS1_SETLENGTH(lenNb, lenNb);

  /*
   * Compute odd part of the Nb
   *    Nb_odd = Nb >> 1
   */
  MCUXCLPKC_FP_CALC_OP1_SHR(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, 1u);

  /* Compute NDash of Nb_odd */
  MCUXCLMATH_FP_NDASH(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB); // MODINV_NB as temp buffer

  MCUXCLMATH_FP_SHIFTMODULUS(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD_SHIFT, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD);

  /* Compute QDash (in MODINV_R) for Nb_odd, with length = length(xb) = lenX + MCUXCLRSA_PKC_WORDSIZE */
  MCUXCLMATH_FP_QDASH(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_R,
                     MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD_SHIFT,
                     MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD,
                     MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, // as temp buffer
                     (uint16_t)(lenX + MCUXCLRSA_PKC_WORDSIZE));

  /* Compute xb (in MODINV_NB) = x * Rnd */
  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS2_SETLENGTH_REG(lenX);
  MCUXCLPKC_FP_CALC_OP2_MUL(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_RND, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_X);

  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS2_SETLENGTH(lenX + MCUXCLRSA_PKC_WORDSIZE, lenNb);

  /* Compute xb_r (in MODINV_NB) = reduced x_b modulo Nb_odd */
  MCUXCLPKC_FP_CALCFUP(mcuxClRsa_ModInv_ReduceBlindedData_FUP, mcuxClRsa_ModInv_ReduceBlindedData_FUP_LEN);

  /*
   * Preform modular inversion of the odd part of the Nb
   *    Yodd_b (in MODINV_X) = xb_r^(-1) mod Nb_odd
   */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(
    mcuxClMath_ModInv(
      MCUXCLPKC_PACKARGS4(
        MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_X,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD,
        MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_R), // as temp buffer
        MCUXCLMATH_XN_NOT_COPRIME));

  /* Compute the new QDash (in MODINV_R), with length = length(Yodd_b_b) = lenNb + MCUXCLRSA_PKC_WORDSIZE */
  MCUXCLMATH_FP_QDASH(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_R,
                     MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD_SHIFT,
                     MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD,
                     MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, // as temp buffer
                     (uint16_t)(lenNb + MCUXCLRSA_PKC_WORDSIZE));


  /* Compute Yodd_b_b (in MODINV_NB) = Yodd_b * Rnd */
  MCUXCLPKC_FP_CALC_OP1_MUL(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_RND, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_X);

  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_PS2_SETLENGTH(lenNb + MCUXCLRSA_PKC_WORDSIZE, lenNb);

  /* Compute Yodd_b_br (in MODINV_NB) = reduced Yodd_b_b modulo Nb_odd */
  MCUXCLPKC_FP_CALCFUP(mcuxClRsa_ModInv_ReduceBlindedData_FUP, mcuxClRsa_ModInv_ReduceBlindedData_FUP_LEN);

  /*
   * Compute T (in MODINV_NB) =  (1 - Yodd_b_br mod 2) * Nb_odd + Yodd_b_br
   * Check the LSbit of Yodd_b_br:
   * if LSbit(Yodd_b_br) == 1 -> (1 - Yodd_b_br mod 2) = 0
   *   T = Yodd_b_br
   * else LSbit(Yodd_b_br) == 0 -> (1 - Yodd_b_br mod 2) = 1 ->
   *   T = Nb_odd + Yodd_b_br
   */

  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_FP_CALC_OP1_LSB0s(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB);

  /* If the zero flag is not set, it means LSbit(Yodd) == 0 */
  uint32_t zeroFlag = MCUXCLPKC_WAITFORFINISH_GETZERO();
  if(MCUXCLPKC_FLAG_NONZERO == zeroFlag)
  {
    MCUXCLPKC_FP_CALC_OP1_ADD(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB, MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB_ODD);
  }

  /* Compute R = T / Rnd */
  MCUXCLMATH_FP_EXACTDIVIDE(MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_R,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_NB,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_RND,
    MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_X,
    lenNb,
    MCUXCLRSA_PKC_WORDSIZE);

  /* Protect the address of the result */
  MCUX_CSSL_DI_EXPUNGE(pR, MCUXCLPKC_OFFSET2PTR(pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_MODINV_R]));

  /* Recover Ps1, Ps2 length and Uptrt */
  MCUXCLPKC_PS1_SETLENGTH_REG(bakPs1LenReg);
  MCUXCLPKC_PS2_SETLENGTH_REG(bakPs2LenReg);
  MCUXCLPKC_SETUPTRT(backupPtrUptrt);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_ModInv,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_InitLocalUptrt),
                            MCUXCLPKC_FP_CALLED_CALC_OP1_SHR,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_NDash),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus),
                            2u*MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_QDash),
                            MCUXCLPKC_FP_CALLED_CALC_OP2_MUL,
                            2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ModInv),
                            MCUXCLPKC_FP_CALLED_CALC_OP1_MUL,
                            MCUXCLPKC_FP_CALLED_CALC_OP1_LSB0s,
                            MCUX_CSSL_FP_CONDITIONAL(MCUXCLPKC_FLAG_NONZERO == zeroFlag, MCUXCLPKC_FP_CALLED_CALC_OP1_ADD),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ExactDivide));
}

