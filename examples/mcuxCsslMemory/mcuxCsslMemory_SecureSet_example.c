/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023, 2025 NXP                                            */
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
 * @example  mcuxCsslMemory_SecureSet_example.c
 * @brief Example for the secure set function
 */

#include <stdbool.h>
#include <stdint.h>
#include <mcuxCsslMemory.h>
#include <mcuxCsslMemory_Examples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>

bool mcuxCsslMemory_SecureSet_example(void)
{
  /* Define data array */
  uint8_t arr[33] = { 0u };

  /* Try to set nothing (length = 0 bytes) => should return success */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(setResult, setToken, mcuxCsslMemory_SecureSet(
  /*  mcuxCsslParamIntegrity_Checksum_t chk */ MCUX_CSSL_PI_PROTECT(arr, 42u, 0u, sizeof(arr)),
  /*  void * pDst                          */ arr,
  /*  uint8_t val                          */ 42u,
  /*  uint32_t length                      */ 0u,
  /*  uint32_t bufLength                   */ sizeof(arr)
  ));

  /* Check the return code of mcuxCsslMemory_SecureSet */
  if(((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureSet) != setToken)) || (MCUXCSSLMEMORY_STATUS_OK != setResult))
  {
    return MCUXCSSLMEMORY_EX_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Try to call the function with NULL as destination => should return invalid parameter error */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(setResult1, setToken1, mcuxCsslMemory_SecureSet(
  /*  mcuxCsslParamIntegrity_Checksum_t chk */ MCUX_CSSL_PI_PROTECT(NULL, 42u, sizeof(arr), sizeof(arr)),
  /*  void * pDst                          */ NULL,
  /*  uint8_t val                          */ 42u,
  /*  uint32_t length                      */ sizeof(arr),
  /*  uint32_t bufLength                   */ sizeof(arr)
  ));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()

  /* Check the return code of mcuxCsslMemory_SecureSet */
  if(((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureSet) != setToken1)) || (MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER != setResult1))
  {
    return MCUXCSSLMEMORY_EX_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Set all bytes in the buffer to 42 => should return success */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(setResult2, setToken2, mcuxCsslMemory_SecureSet(
  /*  mcuxCsslParamIntegrity_Checksum_t chk */ MCUX_CSSL_PI_PROTECT(arr, 42u, sizeof(arr), sizeof(arr)),
  /*  void * pDst                          */ arr,
  /*  uint8_t val                          */ 42u,
  /*  uint32_t length                      */ sizeof(arr),
  /*  uint32_t bufLength                   */ sizeof(arr)
  ));

  /* Check the return code of mcuxCsslMemory_SecureSet */
  if(((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureSet) != setToken2)) || (MCUXCSSLMEMORY_STATUS_OK != setResult2))
  {
    return MCUXCSSLMEMORY_EX_ERROR;
  }

  /* Check that the function works as expected */
  for (uint32_t i = 0u; i < sizeof(arr); ++i) {
    if (arr[i] != 42u) {
      return MCUXCSSLMEMORY_EX_ERROR;
    }
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  return MCUXCSSLMEMORY_EX_OK;
}
