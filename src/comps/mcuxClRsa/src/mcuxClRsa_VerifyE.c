/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2024-2026 NXP                                            */
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

/** @file  mcuxClRsa_VerifyE.c
 *  @brief mcuxClRsa: function, which is called to check if E is FIPS compliant
 *  (i.e., is odd values in the range 2^16 < e < 2^256) and determines its
 *  length without leading zeros..
 */


#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_VerifyE)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRsa_VerifyE(mcuxClSession_Handle_t pSession, mcuxClRsa_KeyEntry_t *pE, uint32_t *exactLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_VerifyE);

  mcuxClRsa_Status_t status = MCUXCLKEY_STATUS_INVALID_INPUT;

  /* Determine the exact length of e */
  uint32_t eLength = pE->keyEntryLength;

  while(eLength > 0U)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pE->keyEntryLength >= e, so pE->keyEntryLength - eLength can't be negatie")
    if(0u != pE->pKeyEntryData[pE->keyEntryLength - eLength])
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    {
      break;
    }
    --eLength;
  }

  /* Check if it is the range 2^16 < e < 2^256 */
  if((eLength > 2U)  && (eLength < 33U))
  {
    /* Check if E is odd */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pE->keyEntryLength must be bigger than 1u when enter this branch")
    if(0x1u == (pE->pKeyEntryData[pE->keyEntryLength - 1U] % 2U))
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    {
      /* Set exact length of E */
      *exactLength = eLength;
      status = MCUXCLKEY_STATUS_OK;
    }
  }

  /* If the exponent E is not FIPS compliant, return MCUXCLKEY_STATUS_INVALID_INPUT */
  if(MCUXCLKEY_STATUS_OK != status)
  {
    MCUXCLSESSION_ERROR(pSession, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRsa_VerifyE);
}
