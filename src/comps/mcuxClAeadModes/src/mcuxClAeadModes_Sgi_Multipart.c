/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

/** @file  mcuxClAeadModes_Sgi_Multipart.c
 *  @brief implementation of the multipart functions of the mcuxClAeadModes component */

#include <mcuxClCore_Platform.h>

#include <internal/mcuxClAeadModes_Common.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClAeadModes_Common_Functions.h>
#include <internal/mcuxClAeadModes_Sgi_Cleanup.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClAeadModes_Sgi_Functions.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <mcuxClAes.h>
#include <mcuxClAead_Types.h>
#include <mcuxClAead_Constants.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <mcuxClCore_Macros.h>
#include <internal/mcuxClMemory_CompareDPASecure_Internal.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClAeadModes_MemoryConsumption.h>
#include <mcuxClMemory.h>
#include <mcuxClResource_Types.h>
#include <internal/mcuxClCrc_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_init_encrypt_decrypt)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_init_encrypt_decrypt(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint32_t inLength,
  uint32_t adataLength,
  uint32_t tagLength,
  uint32_t encDecMode
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_init_encrypt_decrypt);

  MCUX_CSSL_DI_RECORD(tagLen, tagLength); /* Will be balanced after usage in mode->algorithm->init() */

  /* Allocate workarea */
  uint32_t const cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_WorkArea_t));

  mcuxClAeadModes_Context_t * const pCtx = mcuxClAeadModes_castToAeadModesContext(pContext);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  workArea->sgiWa.pKeyChecksums = &(pCtx->cipherCtx.keyContext.keyChecksums);

  MCUX_CSSL_DI_RECORD(MultipartInitEnc_copyKeyContext, (uint32_t)&pCtx->macCtx.keyContext);
  MCUX_CSSL_DI_RECORD(MultipartInitEnc_copyKeyContext, (uint32_t)&pCtx->cipherCtx.keyContext);
  MCUX_CSSL_DI_RECORD(MultipartInitEnc_copyKeyContext, sizeof(mcuxClAes_KeyContext_Sgi_t));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key to SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, key, &(workArea->sgiWa), MCUXCLSGI_DRV_KEY0_OFFSET));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_storeMaskedKeyInCtx_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_storeMaskedKeyInCtx_Sgi(session,
                                                                  key,
                                                                  &(pCtx->cipherCtx.keyContext),
                                                                  &(workArea->sgiWa),
                                                                  MCUXCLSGI_DRV_KEY0_OFFSET,
                                                                  mcuxClKey_getSize(key)));

  /* Copy the key context to mac context as well */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
    (uint8_t*)&pCtx->macCtx.keyContext,
    (uint8_t const*)&pCtx->cipherCtx.keyContext,
    sizeof(mcuxClAes_KeyContext_Sgi_t)));

  pCtx->macCtx.keyContext.sgiCtrlKey = workArea->sgiWa.sgiCtrlKey;
  pCtx->cipherCtx.keyContext.sgiCtrlKey = workArea->sgiWa.sgiCtrlKey;

  pCtx->encDecMode = encDecMode;
  MCUX_CSSL_DI_EXPUNGE(encDecModeDi, encDecMode);
  pCtx->common.mode = mode;

  pCtx->process = mode->algorithm->processEncDec;
  pCtx->protectionToken_process = mode->algorithm->protectionToken_processEncDec;

  /* Clear mac context fields */
  pCtx->macCtx.blockBufferUsed = 0u;
  pCtx->macCtx.dataProcessed = MCUXCLMACMODES_FALSE;
  pCtx->macCtx.totalInput = 0u;

  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_init);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->init(
    session,
    pCtx,
    workArea,
    pNonce,
    nonceLength,
    inLength,
    adataLength,
    tagLength)
  );

  /* Init context CRC */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, MCUXCLAEAD_CONTEXT_SIZE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_init_encrypt_decrypt);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_init_encrypt, mcuxClAead_init_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_init_encrypt(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint32_t inLength,
  uint32_t adataLength,
  uint32_t tagLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_init_encrypt);

  MCUX_CSSL_DI_RECORD(encDecModeDi, MCUXCLAEADMODES_ENCRYPTION); /* Will be balanced in mcuxClAeadModes_init_encrypt_decrypt */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_init_encrypt_decrypt));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_init_encrypt_decrypt(
    session,
    pContext,
    key, mode,
    pNonce,
    nonceLength,
    inLength,
    adataLength,
    tagLength,
    MCUXCLAEADMODES_ENCRYPTION));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_init_encrypt);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_init_decrypt, mcuxClAead_init_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_init_decrypt(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint32_t inLength,
  uint32_t adataLength,
  uint32_t tagLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_init_decrypt);

  MCUX_CSSL_DI_RECORD(encDecModeDi, MCUXCLAEADMODES_DECRYPTION); /* Will be balanced in mcuxClAeadModes_init_encrypt_decrypt */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_init_encrypt_decrypt));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_init_encrypt_decrypt(
    session,
    pContext,
    key,
    mode,
    pNonce,
    nonceLength,
    inLength,
    adataLength,
    tagLength,
    MCUXCLAEADMODES_DECRYPTION));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_init_decrypt);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_process, mcuxClAead_process_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_process(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_process);

  mcuxClAeadModes_Context_t * const pCtx = mcuxClAeadModes_castToAeadModesContext(pContext);

  /* Check if input size will not overflow - SREQI_AEAD_9*/
  if (pCtx->inSize >= (UINT32_MAX - inLength))
  {
    /* No need to clear the context since this is a functional error. */
    MCUXCLSESSION_ERROR(session, MCUXCLAEAD_STATUS_INVALID_PARAM);
  }

  /* Check context CRC */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pCtx, MCUXCLAEAD_CONTEXT_SIZE));

  /* Allocate workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load the key */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session,
                                                                   &(pCtx->cipherCtx.keyContext),
                                                                   &(workArea->sgiWa),
                                                                   MCUXCLSGI_DRV_KEY0_OFFSET,
                                                                   MCUXCLAES_MASKED_KEY_SIZE));

  MCUX_CSSL_FP_EXPECT(pCtx->protectionToken_process);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->process(
    session,
    pCtx,
    workArea,
    pIn,
    inLength,
    pOut,
    pOutLength));

  /* Update context CRC */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, MCUXCLAEAD_CONTEXT_SIZE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_process);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_process_adata, mcuxClAead_process_aad_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_process_adata(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_process_adata);

  mcuxClAeadModes_Context_t * const pCtx = mcuxClAeadModes_castToAeadModesContext(pContext);

  /* Check context CRC */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pCtx, MCUXCLAEAD_CONTEXT_SIZE));

  /* Allocate workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load the key */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session,
                                                                   &(pCtx->cipherCtx.keyContext),
                                                                   &(workArea->sgiWa),
                                                                   MCUXCLSGI_DRV_KEY0_OFFSET,
                                                                   MCUXCLAES_MASKED_KEY_SIZE));

  MCUX_CSSL_FP_EXPECT(pCtx->common.mode->algorithm->protectionToken_processAad);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->common.mode->algorithm->processAad(
    session,
    pCtx,
    workArea,
    pAdata,
    adataLength));

  /* Update context CRC */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_computeContextCrc(pContext, MCUXCLAEAD_CONTEXT_SIZE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_process_adata);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_finish, mcuxClAead_finish_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_finish(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength,
  mcuxCl_Buffer_t pTag
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_finish);

  MCUX_CSSL_DI_RECORD(tag, pTag); /* Will be balanced after usage in mode->algorithm->finish() */

  mcuxClAeadModes_Context_t * const pCtx = mcuxClAeadModes_castToAeadModesContext(pContext);

  /* Check context CRC */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pCtx, MCUXCLAEAD_CONTEXT_SIZE));

  /* Allocate workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load the key */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session,
                                                                   &(pCtx->cipherCtx.keyContext),
                                                                   &(workArea->sgiWa),
                                                                   MCUXCLSGI_DRV_KEY0_OFFSET,
                                                                   MCUXCLAES_MASKED_KEY_SIZE));

  MCUX_CSSL_FP_EXPECT(pCtx->common.mode->algorithm->protectionToken_finish);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->common.mode->algorithm->finish(
    session,
    pCtx,
    workArea,
    pOut,
    pOutLength,
    pTag));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));

  /* Clear cipher key context.
   * Clear the context after the call to mcuxClAeadModes_cleanupOnExit to not loose the key information too soon. */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, &pCtx->cipherCtx.keyContext);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, sizeof(mcuxClAes_KeyContext_Sgi_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *)&pCtx->cipherCtx.keyContext, sizeof(mcuxClAes_KeyContext_Sgi_t)));

  /* Clear mac key context */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, &pCtx->macCtx.keyContext);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, sizeof(mcuxClAes_KeyContext_Sgi_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *)&pCtx->macCtx.keyContext, sizeof(mcuxClAes_KeyContext_Sgi_t)));

  /* Clear counter0 */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, pCtx->counter0);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, MCUXCLAES_BLOCK_SIZE);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *)pCtx->counter0, MCUXCLAES_BLOCK_SIZE));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_finish);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_verify, mcuxClAead_verify_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAeadModes_verify(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pTag,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_verify);

  mcuxClAeadModes_Context_t * const pCtx = mcuxClAeadModes_castToAeadModesContext(pContext);

  MCUX_CSSL_DI_RECORD(tagSize, pCtx->tagSize); /* Will be balanced in mcuxClMemory_compare_dpasecure_int() */
  /* pTag will be protected after mcuxClBuffer_inputBufferToCPU() */

  /* Check context CRC */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_verifyContextCrc));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_verifyContextCrc(session, pContext, MCUXCLAEAD_CONTEXT_SIZE));

  /* Allocate workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  uint8_t *pComputedTag = &workArea->cpuWa.tagBuffer[MCUXCLAEADMODES_TAGLEN_MAX];

  MCUXCLBUFFER_INIT(computedTagBuffer, NULL, pComputedTag, MCUXCLAEADMODES_TAGLEN_MAX);
  MCUX_CSSL_DI_RECORD(computedTag, pComputedTag); /* Will be balanced in mcuxClMemory_compare_dpasecure_int() */
  MCUX_CSSL_DI_RECORD(finishTagbuff, computedTagBuffer); /* Will be balanced after usage in mode->algorithm->finish() */

  /* Request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  /* Initialize the SGI. From this point onwards, returning after any functional error must be done after flushing the SGI. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load the key */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session,
                                                                   &(pCtx->cipherCtx.keyContext),
                                                                   &(workArea->sgiWa),
                                                                   MCUXCLSGI_DRV_KEY0_OFFSET,
                                                                   MCUXCLAES_MASKED_KEY_SIZE));

  MCUX_CSSL_FP_EXPECT(pCtx->common.mode->algorithm->protectionToken_finish);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->common.mode->algorithm->finish(
    session,
    pCtx,
    workArea,
    pOut,
    pOutLength,
    computedTagBuffer));

  /* Prepare the reference tag. For buffer-objects with DMA, this will import the tag to a CPU buffer before comparison. */
  const uint8_t *pReferenceTag;
  mcuxClBuffer_inputBufferToCPU(pTag, 0u, workArea->cpuWa.tagBuffer, &pReferenceTag, pCtx->tagSize);
  MCUX_CSSL_DI_RECORD(referenceTag, pReferenceTag); /* Will be balanced in mcuxClMemory_compare_dpasecure_int() */

  /* Compare authentication tags */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_compare_dpasecure_int));
  MCUX_CSSL_FP_FUNCTION_CALL(compareStatus, mcuxClMemory_compare_dpasecure_int(session, pReferenceTag, pComputedTag, pCtx->tagSize));
  MCUX_CSSL_DI_RECORD(compareStatus, compareStatus);

  mcuxClAead_Status_t retCode = MCUXCLAEAD_STATUS_FAULT_ATTACK;

  if (MCUXCLMEMORY_STATUS_NOT_EQUAL == compareStatus)
  {
    // Tag is invalid
    MCUX_CSSL_DI_EXPUNGE(compareNotOk, MCUXCLAEADMODES_INTERNAL_COMP_NOT_OK);
    retCode = MCUXCLAEAD_STATUS_INVALID_TAG;
  }
  else if (MCUXCLMEMORY_STATUS_EQUAL == compareStatus)
  {
    MCUX_CSSL_DI_EXPUNGE(compareOk, MCUXCLAEADMODES_INTERNAL_COMP_OK);
    retCode = MCUXCLAEAD_STATUS_OK;
  }
  else
  {
    MCUXCLSESSION_FAULT(session, MCUXCLAEAD_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_DI_RECORD(returnCode, retCode);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_cleanupOnExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_cleanupOnExit(session, pCtx, NULL /* key is in context */, cpuWaSizeInWords));

  /* Clear cipher key context.
   * Clear the context after the call to mcuxClAeadModes_cleanupOnExit to not loose the key information too soon. */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, &pCtx->cipherCtx.keyContext);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, sizeof(mcuxClAes_KeyContext_Sgi_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *)&pCtx->cipherCtx.keyContext, sizeof(mcuxClAes_KeyContext_Sgi_t)));

  /* Clear mac key context */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, &pCtx->macCtx.keyContext);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, sizeof(mcuxClAes_KeyContext_Sgi_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *)&pCtx->macCtx.keyContext, sizeof(mcuxClAes_KeyContext_Sgi_t)));

  /* Clear counter0 */
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, pCtx->counter0);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int, MCUXCLAES_BLOCK_SIZE);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *)pCtx->counter0, MCUXCLAES_BLOCK_SIZE));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAeadModes_verify, retCode);
}
