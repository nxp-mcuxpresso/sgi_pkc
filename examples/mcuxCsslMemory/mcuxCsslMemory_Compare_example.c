/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021, 2025-2026 NXP                                       */
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

/** @example  mcuxCsslMemory_Compare_example.c
*  @brief Example constant-time memory compare (CSSL component mcuxCsslMemory) */

#include <mcuxClToolchain.h>
#include <mcuxCsslMemory.h>
#include <mcuxCsslMemory_Examples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>

MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_Compare_example)
{
  /* Define data arrays */
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
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(compareResultZeroLength, compareTokenZeroLength, mcuxCsslMemory_Compare(
  /* mcuxCsslParamIntegrity_Checksum_t chk,*/ MCUX_CSSL_PI_PROTECT(arr_1, arr_2, 0U),
  /* void const * lhs,                    */ arr_1,
  /* void const * rhs,                    */ arr_2,
  /* uint32_t length                      */ 0U
  ));

  /* Check the return code of mcuxCsslMemory_Compare */
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare) != compareTokenZeroLength)
    || (MCUXCSSLMEMORY_STATUS_ZERO_LENGTH != compareResultZeroLength))
  {
    return MCUXCSSLMEMORY_EX_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Compare arr_1 with arr_2 => Should be true */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(compareResultEq, compareTokenEq, mcuxCsslMemory_Compare(
  /* mcuxCsslParamIntegrity_Checksum_t chk,*/ MCUX_CSSL_PI_PROTECT(arr_1, arr_2, sizeof(arr_1)),
  /* void const * lhs,                    */ arr_1,
  /* void const * rhs,                    */ arr_2,
  /* uint32_t length                      */ sizeof(arr_1)));

  /* Check the return code of mcuxCsslMemory_Compare */
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare) != compareTokenEq)
    || (MCUXCSSLMEMORY_STATUS_EQUAL != compareResultEq))
  {
    return MCUXCSSLMEMORY_EX_ERROR;
  }

  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /* Compare arr_1 with arr_3 => Should be false */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(compareResultNotEq, compareTokenNotEq, mcuxCsslMemory_Compare(
  /* mcuxCsslParamIntegrity_Checksum_t chk,*/ MCUX_CSSL_PI_PROTECT(arr_1, arr_3, sizeof(arr_1)),
  /* void const * lhs,                    */ arr_1,
  /* void const * rhs,                    */ arr_3,
  /* uint32_t length                      */ sizeof(arr_1)));

  /* Check the return code of mcuxCsslMemory_Compare */
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare) != compareTokenNotEq)
    || (MCUXCSSLMEMORY_STATUS_NOT_EQUAL != compareResultNotEq))
  {
    return MCUXCSSLMEMORY_EX_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* No error occurred during execution, exit with MCUXCSSLMEMORY_EX_OK */
  return MCUXCSSLMEMORY_EX_OK;
}
