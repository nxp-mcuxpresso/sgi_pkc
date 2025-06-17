/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
 * @file  mcuxClFfdh_PublicKeyLoadAndValidate.c
 * @brief FFDH key agreement function
 */

#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClFfdh.h>
#include <mcuxClKey.h>
#include <mcuxClSession.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClFfdh_Internal.h>
#include <internal/mcuxClFfdh_Internal_PkcDefs.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClMath_Internal_Functions.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

/**
 * @brief FFDH Public Key Load and Validate
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClFfdh_PublicKeyLoadAndValidate)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClFfdh_PublicKeyLoadAndValidate(
  mcuxClSession_Handle_t pSession,
  mcuxClKey_Handle_t publicKey,
  mcuxClFfdh_CpuWa_t* pCpuWorkarea,
  uint32_t* pExpTemp
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClFfdh_PublicKeyLoadAndValidate);

  mcuxClFfdh_DomainParams_t* pDomainParameters = (mcuxClFfdh_DomainParams_t*)mcuxClKey_getTypeInfo(publicKey);
  const uint32_t lenP = pDomainParameters->lenP;
  const uint32_t expOperandSize = pCpuWorkarea->expOperandSize;
  uint16_t* pOperands = MCUXCLPKC_GETUPTRT();

  /* Load public key to PKC buffer FFDH_UPTRTINDEX_T2 */
  uint8_t* pPublicKeyData = MCUXCLPKC_OFFSET2PTR(pOperands[FFDH_UPTRTINDEX_T2]);
  MCUXCLPKC_WAITFORFINISH();
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in the code")
    mcuxClKey_load(pSession, publicKey, &pPublicKeyData, NULL, MCUXCLKEY_ENCODING_SPEC_ACTION_NORMAL)
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
  );

  /* Public Key Validation (PKV) routine according to RFC2631 section 2.1.5.
   * 1. Verify that y lies within the interval [2,p-1]. If it does not,
   *    the key is invalid.
   * 2. Compute y^q mod p. If the result == 1, the key is valid.
   *    Otherwise the key is invalid. */

  /* PKV 1a) Public key lower range check */
  MCUXCLPKC_FP_CALC_OP1_SUB_CONST(FFDH_UPTRTINDEX_T3, FFDH_UPTRTINDEX_T2, 2U);
  if(MCUXCLPKC_FLAG_CARRY == MCUXCLPKC_WAITFORFINISH_GETCARRY())
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  /* PKV 1b) Public key upper range check */
  MCUXCLPKC_FP_CALC_OP1_CMP(FFDH_UPTRTINDEX_T2, FFDH_UPTRTINDEX_P);
  if(MCUXCLPKC_FLAG_CARRY != MCUXCLPKC_WAITFORFINISH_GETCARRY())
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  /* Convert public key to Montgomery representation */
  MCUXCLPKC_FP_CALC_MC1_MM(FFDH_UPTRTINDEX_BASE, FFDH_UPTRTINDEX_T1, FFDH_UPTRTINDEX_T2, FFDH_UPTRTINDEX_P);
  uint8_t* pBase = MCUXCLPKC_OFFSET2PTR(pOperands[FFDH_UPTRTINDEX_BASE]);

  /* Clear garbage above pBase */
  MCUXCLPKC_WAITFORFINISH();
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(&pBase[lenP], expOperandSize - lenP));

  /* The primes in supported RFC7919 finite field groups are all safe primes.
   * This means a prime p is a safe prime when q = (p-1)/2.
   * Therefore we can calculate q = p/2. */
  MCUXCLPKC_FP_CALC_OP1_SHR(FFDH_UPTRTINDEX_EXP, FFDH_UPTRTINDEX_P, 1U);
  /* Clear garbage above exp buffer */
  uint8_t* pExp = MCUXCLPKC_OFFSET2PTR(pOperands[FFDH_UPTRTINDEX_EXP]);
  MCUXCLPKC_WAITFORFINISH();
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(&pExp[lenP], expOperandSize - lenP));
  /* PKV 2) Compute y^q mod p */
  MCUXCLPKC_PS1_SETLENGTH(expOperandSize, expOperandSize);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(MCUXCLMATH_SECMODEXP(
    pSession,
    pExpTemp,
    pDomainParameters->lenQ, /* Length of exponent  */
    FFDH_UPTRTINDEX_EXP,     /* Output -> result, input -> private exponent */
    FFDH_UPTRTINDEX_BASE,    /* Montgomery representation of base */
    FFDH_UPTRTINDEX_P,       /* Modulus */
    FFDH_UPTRTINDEX_T5,      /* iTE - last buffer 6FW */
    FFDH_UPTRTINDEX_T1,      /* Remaining temporary buffers */
    FFDH_UPTRTINDEX_T2,
    FFDH_UPTRTINDEX_T3,
    FFDH_UPTRTINDEX_T4
  ));

  /* Bring result back to normal representation */
  MCUXCLPKC_FP_CALC_MC1_MR(FFDH_UPTRTINDEX_T1, FFDH_UPTRTINDEX_EXP, FFDH_UPTRTINDEX_P);
  MCUXCLPKC_FP_CALC_MC1_MS(FFDH_UPTRTINDEX_T1, FFDH_UPTRTINDEX_T1, FFDH_UPTRTINDEX_P, FFDH_UPTRTINDEX_P);

  /* Check if result == 1 then the key is valid */
  MCUXCLPKC_FP_CALC_OP1_SUB_CONST(FFDH_UPTRTINDEX_T1, FFDH_UPTRTINDEX_T1, 1U);
  if(MCUXCLPKC_FLAG_ZERO != MCUXCLPKC_WAITFORFINISH_GETZERO())
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(
    mcuxClFfdh_PublicKeyLoadAndValidate,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_load),
    MCUXCLPKC_FP_CALLED_CALC_OP1_SUB_CONST,
    MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
    MCUXCLPKC_FP_CALLED_CALC_MC1_MM,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int)
      ,
    MCUXCLPKC_FP_CALLED_CALC_OP1_SHR,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_SecModExp),
    MCUXCLPKC_FP_CALLED_CALC_MC1_MR,
    MCUXCLPKC_FP_CALLED_CALC_MC1_MS,
    MCUXCLPKC_FP_CALLED_CALC_OP1_SUB_CONST
  );
}
