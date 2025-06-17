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

/** @file  mcuxClRsa_TestPQDistance.c
 *  @brief mcuxClRsa: function, which is called to test |p - q| <= 2^(nlen/2 - 100).
 *  This is a verification required by FIPS 186-4 (Appendix B.3.3, step 5.4).
 *  Verification is done by checking the 100 MSbits of p and q. If they are equal,
 *  test fail.
 *
 *  The implementation assumes that:
 *  - pLen = qLen = nlen/2 = primeByteLength
 *  - primeByteLength is a multiple of PKC wordsize.
 *  - PKC wordsize is not greater than 128 bits
 *
 *  NOTE: This function will require adaptation if need to support primeByteLength
 *  that is not multiple of PKC word.
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal_Functions.h>
#include <internal/mcuxClPrng_Internal_Functions.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_TestPQDistance_FUP.h>
#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Macros.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_TestPQDistance)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_TestPQDistance(mcuxClSession_Handle_t pSession, uint32_t iP_iQ_iT, uint32_t primeByteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_TestPQDistance);

  /* Set init status to ERROR */
  mcuxClRsa_Status_t status = MCUXCLKEY_STATUS_ERROR;

  /* Backup Uptrt to recover in the end */
  const uint16_t *backupPtrUptrt = MCUXCLPKC_GETUPTRT();

  /* Backup Ps1 length to recover in the end */
  uint32_t backupPs1LenReg = MCUXCLPKC_PS1_GETLENGTH_REG();

  /* Create and set local Uptrt table. */
  uint16_t pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_UPTRT_SIZE];

  const uint32_t pkcOperandLen = 128u / 8u;
  const uint32_t pkcPrimeLen = primeByteLength;
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pkcPrimeLen, MCUXCLRSA_MIN_MODLEN / 2U, MCUXCLRSA_MAX_MODLEN / 2U, MCUXCLRSA_STATUS_INVALID_INPUT)

  /* Get iP, iQ and iT indices */
  uint32_t uptrtIndexP = (iP_iQ_iT >> 16) & 0xFFu;
  uint32_t uptrtIndexQ = (iP_iQ_iT >> 8) & 0xFFu;
  uint32_t uptrtIndexT = (iP_iQ_iT) & 0xFFu;

  pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_P128MSB] = (uint16_t)((backupPtrUptrt[uptrtIndexP] + pkcPrimeLen - pkcOperandLen) & 0xFFFFu); /* offset to the 128 MSbits */
  pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_Q128MSB] = (uint16_t)((backupPtrUptrt[uptrtIndexQ] + pkcPrimeLen - pkcOperandLen) & 0xFFFFu); /* offset to the 128 MSbits */
  pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T1] = backupPtrUptrt[uptrtIndexT];
  pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T2] = (uint16_t)((pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T1] + pkcOperandLen) & 0xFFFFu);
  pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_RAND] = (uint16_t)((pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T2] + pkcOperandLen) & 0xFFFFu);
  /* Set shift value (128b-100b = 27b) */
  pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_CONSTANT28] = 28u;

  uint8_t * pRand = MCUXCLPKC_OFFSET2PTR(pOperands[MCUXCLRSA_INTERNAL_TESTPQDISTANCE_RAND]);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate_Internal(pRand, pkcOperandLen));

  MCUXCLPKC_WAITFORREADY();
  MCUXCLPKC_SETUPTRT(pOperands);

  /* Set Ps1 length */
  MCUXCLPKC_PS1_SETLENGTH_REG(pkcOperandLen);  /* Don't care mclen @hi16. */

  MCUXCLPKC_FP_CALCFUP(mcuxClRsa_TestPQDistance_FUP,
          mcuxClRsa_TestPQDistance_FUP_LEN);
  uint32_t zeroFlag_check = MCUXCLPKC_WAITFORFINISH_GETZERO();

  /* Check FIPS 186-4 verification (100 MS bits of p and q are not equal) */
  if(MCUXCLPKC_FLAG_NONZERO == zeroFlag_check)
  {
    /* 100 MS bits of p and q are not equal */
    status = MCUXCLRSA_STATUS_KEYGENERATION_OK;
  }

  /* Recover Ps1 length and Uptrt*/
  MCUXCLPKC_PS1_SETLENGTH_REG(backupPs1LenReg);
  MCUXCLPKC_SETUPTRT(backupPtrUptrt);

  /* If the FIPS 186-4 verification is not successful return MCUXCLKEY_STATUS_ERROR */
  if(MCUXCLRSA_STATUS_KEYGENERATION_OK != status)
  {
    /* FIPS verification of first 100 MS bits of p and q are not equal, is not successful*/
    MCUXCLSESSION_ERROR(pSession, status);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_TestPQDistance,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_Internal),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup)
                            );
}
