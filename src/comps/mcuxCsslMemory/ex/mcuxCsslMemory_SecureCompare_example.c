/*--------------------------------------------------------------------------*/
/* Copyright 2023, 2025-2026 NXP                                            */
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

/** @example  mcuxCsslMemory_SecureCompare_example.c
 *  @brief Example constant-time secure compare (CSSL component mcuxCsslMemory) */

#include <mcuxClToolchain.h>
#include <mcuxCsslMemory_Examples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslMemory_Constants.h>
#include <mcuxCsslMemory_SecureCompare.h>

MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_SecureCompare_example)
{
  /* Define data array */
  ALIGNED uint8_t arr_1[] = {0xe4u, 0xf9u, 0x26u, 0x4cu, 0x65u, 0xe2u, 0x13u, 0xa3u,
                            0x9au, 0x40u, 0xd7u, 0x87u, 0xccu, 0x0bu, 0x31u, 0x18u,
                            0xacu, 0x55u, 0xb5u, 0x7du, 0x06u, 0x7fu, 0xceu, 0xe4u,
                            0xb2u, 0x7eu, 0xd5u, 0xaau, 0x90u, 0x9au, 0x42u, 0x56u,
                            0x76u};
  ALIGNED uint8_t arr_2[] = {0xe4u, 0xf9u, 0x26u, 0x4cu, 0x65u, 0xe2u, 0x13u, 0xa3u,
                            0x9au, 0x40u, 0xd7u, 0x87u, 0xccu, 0x0bu, 0x31u, 0x18u,
                            0xacu, 0x55u, 0xb5u, 0x7du, 0x06u, 0x7fu, 0xceu, 0xe4u,
                            0xb2u, 0x7eu, 0xd5u, 0xaau, 0x90u, 0x9au, 0x42u, 0x56u,
                            0x76u};
  ALIGNED uint8_t arr_3[] = {0x00u, 0xf9u, 0x26u, 0x4cu, 0x65u, 0xe2u, 0x13u, 0xa3u,
                            0x9au, 0x40u, 0xd7u, 0x87u, 0xccu, 0x0bu, 0x31u, 0x18u,
                            0xacu, 0x55u, 0xb5u, 0x7du, 0x06u, 0x7fu, 0xceu, 0xe4u,
                            0xb2u, 0x7eu, 0xd5u, 0xaau, 0x90u, 0x9au, 0x42u, 0x56u,
                            0x76u};

  /* Pass length as zero => Should result in the zero length return code. */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(secureCompareResultZeroLength, secureCompareTokenZeroLength, mcuxCsslMemory_SecureCompare(
  /* mcuxCsslParamIntegrity_Checksum_t chk,*/ MCUX_CSSL_PI_PROTECT(arr_1, arr_2, 0U),
  /* void const * lhs,                    */ arr_1,
  /* void const * rhs,                    */ arr_2,
  /* uint32_t length                      */ 0U));

  /* Check the return code of mcuxCsslMemory_SecureCompare */
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureCompare) != secureCompareTokenZeroLength)
    || (MCUXCSSLMEMORY_STATUS_ZERO_LENGTH != secureCompareResultZeroLength))
  {
      return MCUXCSSLMEMORY_EX_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /* Compare arr_1 with arr_2 => Should be true */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(secureCompareResultEq, secureCompareTokenEq, mcuxCsslMemory_SecureCompare(
  /*  mcuxCsslParamIntegrity_Checksum_t chk */ MCUX_CSSL_PI_PROTECT(arr_1, arr_2, sizeof(arr_1)),
  /*  void * pLhs                          */ arr_1,
  /*  void * pRhs                          */ arr_2,
  /*  uint32_t length                      */ sizeof(arr_1)
  ));

  /* Check the return code of mcuxCsslMemory_SecureCompare */
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureCompare) != secureCompareTokenEq) 
     || (MCUXCSSLMEMORY_STATUS_EQUAL != secureCompareResultEq))
  {
    return MCUXCSSLMEMORY_EX_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /* Compare arr_1 with arr_3 => Should be false */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(secureCompareResultNotEq, secureCompareTokenNotEq, mcuxCsslMemory_SecureCompare(
  /*  mcuxCsslParamIntegrity_Checksum_t chk */ MCUX_CSSL_PI_PROTECT(arr_1, arr_3, sizeof(arr_1)),
  /*  void * pLhs                          */ arr_1,
  /*  void * pRhs                          */ arr_3,
  /*  uint32_t length                      */ sizeof(arr_1)
  ));

  /* Check the return code of mcuxCsslMemory_SecureCompare */
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_SecureCompare) != secureCompareTokenNotEq)
    || (MCUXCSSLMEMORY_STATUS_NOT_EQUAL != secureCompareResultNotEq))
  {
    return MCUXCSSLMEMORY_EX_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  return MCUXCSSLMEMORY_EX_OK;
}
