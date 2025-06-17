/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * \file  mcuxClBuffer.c
 * \brief Provides the internal implementation for the plain C pointer buffer types.
 */


#include <mcuxClToolchain.h>
#include <mcuxClCore_Platform.h>

#include <mcuxClBuffer.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_export)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClBuffer_Status_t) mcuxClBuffer_export(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_export);

  // Balance the SC for buffer / memory copy params
  MCUX_CSSL_DI_RECORD(copyParamsSrc /* Not used */, pSrc);
  MCUX_CSSL_DI_RECORD(copyParamsDst /* Not used */, bufDst);
  MCUX_CSSL_DI_RECORD(copyParamsDst /* Not used */, offset);
  MCUX_CSSL_DI_RECORD(copyParamsLength /* Not used */, byteLength);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(bufDst, offset, pSrc, byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClBuffer_export, MCUXCLBUFFER_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_import)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClBuffer_Status_t) mcuxClBuffer_import(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_import);

  // Balance the SC for buffer / memory copy params
  MCUX_CSSL_DI_RECORD(copyParamsDst /* Not used */, pDst);
  MCUX_CSSL_DI_RECORD(copyParamsSrc /* Not used */, bufSrc);
  MCUX_CSSL_DI_RECORD(copyParamsSrc /* Not used */, offset);
  MCUX_CSSL_DI_RECORD(copyParamsLength /* Not used */, byteLength);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(bufSrc, offset, pDst, byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClBuffer_import, MCUXCLBUFFER_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_read)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_read);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(pDst, &bufSrc[offset], byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_read,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_read_word)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_word(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_read_word);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pDst, &bufSrc[offset], byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_read_word,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_read_reverse)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_reverse(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_read_reverse);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_reversed_int(pDst, &bufSrc[offset], byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_read_reverse,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_reversed_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_read_secure)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_secure(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_read_secure);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(pDst, &bufSrc[offset], byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_read_secure,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_read_secure_reverse)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_secure_reverse(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_read_secure_reverse);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_reversed_int(pDst, &bufSrc[offset], byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_read_secure_reverse,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_reversed_int)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_write)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_write);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(&bufDst[offset], pSrc, byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_write,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_write_word)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write_word(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_write_word);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(&bufDst[offset], pSrc, byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_write_word,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_write_reverse)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write_reverse(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_write_reverse);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_reversed_int(&bufDst[offset], pSrc, byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_write_reverse,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_reversed_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_write_secure)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write_secure(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_write_secure);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(&bufDst[offset], pSrc, byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_write_secure,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_write_secure_reverse)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_write_secure_reverse(mcuxCl_Buffer_t bufDst, uint32_t offset, const uint8_t *pSrc, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_write_secure_reverse);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_reversed_int(&bufDst[offset], pSrc, byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_write_secure_reverse,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_reversed_int)
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClBuffer_read_withoutDestIncrement)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClBuffer_read_withoutDestIncrement(mcuxCl_InputBuffer_t bufSrc, uint32_t offset, uint8_t *pDst, uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClBuffer_read_withoutDestIncrement);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_withoutDstIncrement_int(pDst, &bufSrc[offset], byteLength));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClBuffer_read_withoutDestIncrement,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_withoutDstIncrement_int)
  );
}

