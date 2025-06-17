/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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

/** @file  mcuxClPadding.c
 *  @brief implementation of padding functions for different components */

#include <mcuxClToolchain.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClSession.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClPadding.h>
#include <mcuxClBuffer.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPrng_Internal.h>

#define MCUXCLPADDING_ISO_PADDING_BYTE (0x80u)

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_None, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_None(
  mcuxClSession_Handle_t session,
  uint32_t blockLength UNUSED_PARAM,
  mcuxCl_InputBuffer_t pIn UNUSED_PARAM,
  uint32_t inOffset UNUSED_PARAM,
  uint32_t lastBlockLength,
  uint32_t totalInputLength UNUSED_PARAM,
  uint8_t * const pOut UNUSED_PARAM,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_None);

  if(0u != lastBlockLength)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLPADDING_STATUS_ERROR);
  }

  *pOutLength = 0u;
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_None);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_removePadding_Default, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_Default(
  mcuxClSession_Handle_t session,
  uint32_t blockLength UNUSED_PARAM,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_removePadding_Default);

  /* Copy all bytes in the last block to the output buffer, no removal to be done */
  MCUX_CSSL_DI_RECORD(bufferWrite, (uint32_t) pOut);
  MCUX_CSSL_DI_RECORD(bufferWrite, outOffset);
  MCUX_CSSL_DI_RECORD(bufferWrite, (uint32_t) pIn);
  MCUX_CSSL_DI_RECORD(bufferWrite, lastBlockLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(pOut, outOffset, pIn, lastBlockLength));

  *pOutLength = lastBlockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_Default,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_removePadding_None, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_None(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength UNUSED_PARAM,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_removePadding_None);

  /* If no special padding is set - return the full last block */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPadding_removePadding_Default(
    session,
    blockLength,
    pIn,
    blockLength,
    pOut,
    outOffset,
    pOutLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_None,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_Default));
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_ISO9797_1_Method1, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_ISO9797_1_Method1(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_ISO9797_1_Method1);

  if((0u != totalInputLength) /* special case for zero-padding: add a padding block if totalInputLength is 0 */
       && (0u == lastBlockLength))
  {
    /* No padding needed */
    *pOutLength = 0;
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_ISO9797_1_Method1);
  }

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(lastBlockLength, 0u, blockLength, MCUXCLPADDING_STATUS_ERROR)
  uint32_t paddingBytes = blockLength - lastBlockLength;

  MCUX_CSSL_DI_RECORD(memorySet, pOut + lastBlockLength);
  MCUX_CSSL_DI_RECORD(memorySet, paddingBytes);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(pOut + lastBlockLength, 0x00u, paddingBytes));

  MCUX_CSSL_DI_RECORD(bufferRead, (uint32_t) pIn);
  MCUX_CSSL_DI_RECORD(bufferRead, inOffset);
  MCUX_CSSL_DI_RECORD(bufferRead, (uint32_t) pOut);
  MCUX_CSSL_DI_RECORD(bufferRead, lastBlockLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, inOffset, pOut, lastBlockLength));

  *pOutLength = blockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_ISO9797_1_Method1,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_removePadding_ISO9797_1_Method1, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_ISO9797_1_Method1(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_removePadding_ISO9797_1_Method1);

  if(lastBlockLength != blockLength)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLPADDING_STATUS_ERROR);
  }

  /* ISO9797_1_Method1 padding cannot be removed - return full block */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPadding_removePadding_Default(
    session,
    blockLength,
    pIn,
    blockLength,
    pOut,
    outOffset,
    pOutLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_ISO9797_1_Method1,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_Default));
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is defined indeed")
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_ISO9797_1_Method2, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_ISO9797_1_Method2 (
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength UNUSED_PARAM,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_ISO9797_1_Method2);

  uint8_t *pOutPtr = (uint8_t *) pOut;

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(blockLength, 1u, 16u, MCUXCLPADDING_STATUS_ERROR)
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(lastBlockLength, 0u, blockLength - 1u, MCUXCLPADDING_STATUS_ERROR)

  pOutPtr += lastBlockLength;
  *pOutPtr = MCUXCLPADDING_ISO_PADDING_BYTE;
  pOutPtr++;

  uint32_t paddingBytes = blockLength - lastBlockLength - 1u;

  MCUX_CSSL_DI_RECORD(memorySet, pOutPtr);
  MCUX_CSSL_DI_RECORD(memorySet, paddingBytes);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int((uint8_t *) pOutPtr, 0x00u, paddingBytes));
  MCUX_CSSL_DI_RECORD(bufferRead, (uint32_t) pIn);
  MCUX_CSSL_DI_RECORD(bufferRead, inOffset);
  MCUX_CSSL_DI_RECORD(bufferRead, (uint32_t) pOut);
  MCUX_CSSL_DI_RECORD(bufferRead, lastBlockLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, inOffset, pOut, lastBlockLength));

  *pOutLength = blockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_ISO9797_1_Method2,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_MAC_ISO9797_1_Method2(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2);
  if(blockLength == lastBlockLength)
  {
    /* No padding needed */
    *pOutLength = 0;
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2);
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPadding_addPadding_ISO9797_1_Method2(
    session,
    blockLength,
    pIn,
    inOffset,
    lastBlockLength,
    totalInputLength,
    pOut,
    pOutLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method2));
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_removePadding_ISO9797_1_Method2, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_ISO9797_1_Method2(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_removePadding_ISO9797_1_Method2);

  /* DI balance the calls to the memory functions */
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, (uint32_t)pOut);
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, outOffset);
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, 5u * (uint32_t)pIn);
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(blockLength));

  if(lastBlockLength != blockLength)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLPADDING_STATUS_ERROR);
  }

  const uint8_t randomMaskByte = (uint8_t)(mcuxClPrng_generate_word() & 0xFFu);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XORWithConst_secure_int(pIn, pIn, randomMaskByte, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(blockLength)));

  /* check the last bytes of the block, there must be all zero bytes until we reach the padding byte */
  uint32_t remainingBytes = blockLength;
  for(; remainingBytes > 0u; --remainingBytes)
  {
    uint8_t currentByte = pIn[remainingBytes - 1u];
    if((MCUXCLPADDING_ISO_PADDING_BYTE ^ randomMaskByte) == currentByte)
    {
      break;
    }

    if(randomMaskByte != currentByte)
    {
      /* padding error detected */
      MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_ISO9797_1_Method2);
    }
  }

  if(0u == remainingBytes)
  {
    /* padding error detected - padding byte not found */
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_ISO9797_1_Method2);
  }

  /* one more decrease for the padding byte */
  remainingBytes--;
  /* DI balance the use remainingBytes in the called memory functions*/
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, remainingBytes);
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(remainingBytes));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XORWithConst_secure_int(pIn, pIn, randomMaskByte, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(remainingBytes)));

  /* copy remaining bytes to output */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(pOut, outOffset, pIn, remainingBytes));

  *pOutLength = remainingBytes;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_ISO9797_1_Method2,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XORWithConst_secure_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XORWithConst_secure_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_PKCS7, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void)  mcuxClPadding_addPadding_PKCS7 (
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength UNUSED_PARAM,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_PKCS7);

  if((blockLength <= 1u) || (blockLength > 255u))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLPADDING_STATUS_ERROR);
  }

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(lastBlockLength, 0u, blockLength, MCUXCLPADDING_STATUS_ERROR)
  uint32_t paddingBytes = blockLength - lastBlockLength;

  /*The value of paddingBytes is between 0 and 255, so that it always fits in a uint8_t data type*/
  MCUX_CSSL_DI_RECORD(memorySet, pOut + lastBlockLength);
  MCUX_CSSL_DI_RECORD(memorySet, paddingBytes);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(pOut + lastBlockLength, (uint8_t)(paddingBytes & 0xFFu), paddingBytes));
  MCUX_CSSL_DI_RECORD(bufferRead, (uint32_t) pIn);
  MCUX_CSSL_DI_RECORD(bufferRead, inOffset);
  MCUX_CSSL_DI_RECORD(bufferRead, (uint32_t) pOut);
  MCUX_CSSL_DI_RECORD(bufferRead, lastBlockLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, inOffset, pOut, lastBlockLength));

  *pOutLength = blockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_PKCS7,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_removePadding_PKCS7, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_PKCS7(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_removePadding_PKCS7);

  /* DI balance the calls to the memory functions */
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, (uint32_t)pOut);
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, outOffset);
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, 5u * (uint32_t)pIn);
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(blockLength));

  if(lastBlockLength != blockLength)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLPADDING_STATUS_ERROR);
  }

  const uint8_t randomMaskByte = (uint8_t) (mcuxClPrng_generate_word() & 0xFFu);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XORWithConst_secure_int(pIn, pIn, randomMaskByte, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(blockLength)));

  /* last byte of the block - the amount of padding bytes to remove. Masked with mask. */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(blockLength, 1u, UINT32_MAX, MCUXCLPADDING_STATUS_ERROR)
  uint8_t byteCheckMasked = pIn[blockLength - 1u];
  uint8_t byteCheck = byteCheckMasked ^ randomMaskByte;

  /* Padding byte must be in [1, blockLength] as PKCS7 padding adds at least one byte, and at most one block of padding. */
  if((0u == byteCheck) || (byteCheck > blockLength))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLPADDING_STATUS_ERROR);
  }

  /* check that the last byteCheck bytes in the last block are equal to byteCheck */
  for(uint8_t i = byteCheck; i > 0u; i--)
  {
    if(pIn[blockLength - i] != byteCheckMasked)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_PKCS7);
    }
  }

  /* copy remaining bytes to output */
  uint32_t remainingBytes = blockLength - (uint32_t)byteCheck;
  /* DI balance the use remainingBytes in the called memory functions*/
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, remainingBytes);
  MCUX_CSSL_DI_RECORD(memoryFunctionCalls, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(remainingBytes));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XORWithConst_secure_int(pIn, pIn, randomMaskByte, MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(remainingBytes)));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(pOut, outOffset, pIn, remainingBytes));

  *pOutLength = remainingBytes;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_PKCS7,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XORWithConst_secure_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XORWithConst_secure_int),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_Random, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_Random(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_Random);

  /* Empty input - return */
  if(0u == totalInputLength)
  {
    *pOutLength = 0u;
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_Random);
  }

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(lastBlockLength, 0u, blockLength, MCUXCLPADDING_STATUS_ERROR)
  uint32_t paddingBytes = blockLength - lastBlockLength;

  if(0u != paddingBytes)
  {
    MCUXCLBUFFER_INIT(pOutBuf, NULL, pOut + lastBlockLength, paddingBytes);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPrng_generate(session, pOutBuf, paddingBytes));
  }

  MCUX_CSSL_DI_RECORD(bufferRead, (uint32_t) pIn);
  MCUX_CSSL_DI_RECORD(bufferRead, inOffset);
  MCUX_CSSL_DI_RECORD(bufferRead, (uint32_t) pOut);
  MCUX_CSSL_DI_RECORD(bufferRead, lastBlockLength);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pIn, inOffset, pOut, lastBlockLength));

  *pOutLength = blockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_Random,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_removePadding_Stream, mcuxClPadding_removePaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_removePadding_Stream(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  uint8_t * const pIn,
  uint32_t lastBlockLength,
  mcuxCl_Buffer_t pOut,
  uint32_t outOffset,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_removePadding_Stream);

  /* For stream ciphers - return only lastBlockLength */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPadding_removePadding_Default(
    session,
    blockLength,
    pIn,
    lastBlockLength,
    pOut,
    outOffset,
    pOutLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_removePadding_Stream,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_removePadding_Default));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_Stream, mcuxClPadding_addPaddingMode_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPadding_addPadding_Stream(
  mcuxClSession_Handle_t session,
  uint32_t blockLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_Stream);

  if(0u == lastBlockLength)
  {
    *pOutLength = 0u;
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_Stream);
  }

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPadding_addPadding_Random(
    session,
    blockLength,
    pIn,
    inOffset,
    lastBlockLength,
    totalInputLength,
    pOut,
    pOutLength));

  *pOutLength = lastBlockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClPadding_addPadding_Stream,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_Random));
}
