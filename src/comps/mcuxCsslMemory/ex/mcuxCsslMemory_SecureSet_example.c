/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023, 2025 NXP                                            */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
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

MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_SecureSet_example)
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
