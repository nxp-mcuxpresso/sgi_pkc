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

/** @file  mcuxClAeadModes_Sgi_Oneshot.c
 *  @brief implementation of the one shot functions of the mcuxClAeadModes component */

#include <mcuxClCore_Platform.h>

#include <internal/mcuxClAeadModes_Common.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClSgi_Drv.h>
#include <mcuxClAes.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <mcuxClAead_Constants.h>
#include <internal/mcuxClAeadModes_Common_Functions.h>
#include <internal/mcuxClAeadModes_Sgi_Cleanup.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <mcuxClCore_Macros.h>
#include <internal/mcuxClMemory_CompareDPASecure_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClMemory.h>
#include <internal/mcuxClSgi_Utils.h>

#include <mcuxClResource_Types.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_encrypt, mcuxClAead_encrypt_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_encrypt(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength,
  mcuxCl_Buffer_t pTag,
  uint32_t tagLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_encrypt);

  /* Assert that inLength + *pOutLength will not overflow.
   * *pOutLength is overwritten to 0 in mcuxClAead.c, so no input can possibly trigger this. */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(*pOutLength, 0u, (UINT32_MAX - inLength), MCUXCLAEAD_STATUS_INVALID_PARAM);

  MCUX_CSSL_DI_RECORD(tag, pTag); /* Will be balanced after usage in mode->algorithm->finish() */
  MCUX_CSSL_DI_RECORD(tagLen, tagLength);  /* Will be balanced after usage in mode->algorithm->init() */

  /* Allocate workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  const uint32_t ctxSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_Context_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_Context_t*, aeadCtx, mcuxClSession_allocateWords_cpuWa(session, ctxSizeInWords));

  workArea->sgiWa.pKeyChecksums = &(aeadCtx->cipherCtx.keyContext.keyChecksums);
  /* Initialize/request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key to SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, key, &(workArea->sgiWa), MCUXCLSGI_DRV_KEY0_OFFSET));

  MCUX_CSSL_DI_RECORD(MultipartInitDec_copyKeyContext, (uint32_t)&aeadCtx->macCtx.keyContext.keyChecksums);
  MCUX_CSSL_DI_RECORD(MultipartInitDec_copyKeyContext, (uint32_t)&aeadCtx->cipherCtx.keyContext.keyChecksums);
  MCUX_CSSL_DI_RECORD(MultipartInitDec_copyKeyContext, sizeof(aeadCtx->cipherCtx.keyContext.keyChecksums));
  /* Copy the key context to mac context as well */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
    (uint8_t*)&aeadCtx->macCtx.keyContext.keyChecksums,
    (uint8_t const*)&aeadCtx->cipherCtx.keyContext.keyChecksums,
    sizeof(aeadCtx->cipherCtx.keyContext.keyChecksums)));

  aeadCtx->macCtx.keyContext.sgiCtrlKey = workArea->sgiWa.sgiCtrlKey;
  aeadCtx->cipherCtx.keyContext.sgiCtrlKey = workArea->sgiWa.sgiCtrlKey;

  uint32_t outputSize = 0u;

  aeadCtx->common.mode = mode;
  aeadCtx->encDecMode = MCUXCLAEADMODES_ENCRYPTION;

  /* Clear mac context fields */
  aeadCtx->macCtx.blockBufferUsed = 0u;
  aeadCtx->macCtx.dataProcessed = MCUXCLMACMODES_FALSE;
  aeadCtx->macCtx.totalInput = 0u;

  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_init);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->init(
    session,
    aeadCtx,
    workArea,
    pNonce,
    nonceLength,
    inLength,
    adataLength,
    tagLength));

  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_processAad);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->processAad(session, aeadCtx, workArea, pAdata, adataLength));

  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_processEncDec);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->processEncDec(session, aeadCtx, workArea, pIn, inLength, pOut, &outputSize));

  MCUXCLBUFFER_DERIVE_RW(outBuf, pOut, outputSize);
  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_finish);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->finish(session, aeadCtx, workArea, outBuf, &outputSize, pTag));

  /* outputSize is bounded by inLength */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(outputSize, 0u, inLength, MCUXCLAEAD_STATUS_INVALID_PARAM)
  *pOutLength += outputSize;

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_cleanupOnOneshotExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_cleanupOnOneshotExit(session, key, cpuWaSizeInWords + ctxSizeInWords));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAeadModes_encrypt);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_decrypt, mcuxClAead_decrypt_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAeadModes_decrypt(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength,
  mcuxCl_InputBuffer_t pTag,
  uint32_t tagLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAeadModes_decrypt);

  /* Assert that inLength + *pOutLength will not overflow.
   * *pOutLength is overwritten to 0 in mcuxClAead.c, so no input can possibly trigger this. */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(*pOutLength, 0u, (UINT32_MAX - inLength), MCUXCLAEAD_STATUS_INVALID_PARAM);

  MCUX_CSSL_DI_RECORD(tagSize, 2u * tagLength); /* Will be balanced in mode->algorithm->init() and mcuxClMemory_compare_dpasecure_int() */
  /* pTag will be protected after mcuxClBuffer_inputBufferToCPU() */

  /* Allocate workarea */
  const uint32_t cpuWaSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_WorkArea_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_WorkArea_t*, workArea, mcuxClSession_allocateWords_cpuWa(session, cpuWaSizeInWords));

  /* Prepare a buffer for the to-be-computed tag */
  uint8_t *pComputedTag = &workArea->cpuWa.tagBuffer[MCUXCLAEADMODES_TAGLEN_MAX];
  MCUXCLBUFFER_INIT(computedTagBuffer, NULL, pComputedTag, MCUXCLAEADMODES_TAGLEN_MAX);
  MCUX_CSSL_DI_RECORD(computedTag, pComputedTag); /* Will be balanced in mcuxClMemory_compare_dpasecure_int() */
  MCUX_CSSL_DI_RECORD(computedTagBuffer, computedTagBuffer); /* Will be balanced after usage in mode->algorithm->finish() */

  const uint32_t ctxSizeInWords = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(mcuxClAeadModes_Context_t));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateWords_cpuWa));
  MCUX_CSSL_FP_FUNCTION_CALL(mcuxClAeadModes_Context_t*, aeadCtx, mcuxClSession_allocateWords_cpuWa(session, ctxSizeInWords));

  workArea->sgiWa.pKeyChecksums = &(aeadCtx->cipherCtx.keyContext.keyChecksums);

  /* Initialize/request SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(session, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));


  /* Load key to SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, key, &(workArea->sgiWa), MCUXCLSGI_DRV_KEY0_OFFSET));

  MCUX_CSSL_DI_RECORD(MultipartInitDec_copyKeyContext, (uint32_t)&aeadCtx->macCtx.keyContext.keyChecksums);
  MCUX_CSSL_DI_RECORD(MultipartInitDec_copyKeyContext, (uint32_t)&aeadCtx->cipherCtx.keyContext.keyChecksums);
  MCUX_CSSL_DI_RECORD(MultipartInitDec_copyKeyContext, sizeof(aeadCtx->cipherCtx.keyContext.keyChecksums));
  /* Copy the key context to mac context as well */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
    (uint8_t*)&aeadCtx->macCtx.keyContext.keyChecksums,
    (uint8_t const*)&aeadCtx->cipherCtx.keyContext.keyChecksums,
    sizeof(aeadCtx->cipherCtx.keyContext.keyChecksums)));
  aeadCtx->macCtx.keyContext.sgiCtrlKey = workArea->sgiWa.sgiCtrlKey;
  aeadCtx->cipherCtx.keyContext.sgiCtrlKey = workArea->sgiWa.sgiCtrlKey;

  uint32_t outputSize = 0u;

  aeadCtx->common.mode = mode;
  aeadCtx->encDecMode = MCUXCLAEADMODES_DECRYPTION;

  /* Clear mac context fields */
  aeadCtx->macCtx.blockBufferUsed = 0u;
  aeadCtx->macCtx.dataProcessed = MCUXCLMACMODES_FALSE;
  aeadCtx->macCtx.totalInput = 0u;

  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_init);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->init(
    session,
    aeadCtx,
    workArea,
    pNonce,
    nonceLength,
    inLength,
    adataLength,
    tagLength));

  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_processAad);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->processAad(
    session,
    aeadCtx,
    workArea,
    pAdata,
    adataLength));

  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_processEncDec);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->processEncDec(
    session,
    aeadCtx,
    workArea,
    pIn,
    inLength,
    pOut,
    &outputSize));

  /* outputSize is bounded by inLength */
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(outputSize, 0u, inLength, MCUXCLAEAD_STATUS_INVALID_PARAM)
  MCUXCLBUFFER_DERIVE_RW(outBuf, pOut, outputSize);
  MCUX_CSSL_FP_EXPECT(mode->algorithm->protectionToken_finish);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->algorithm->finish(
    session,
    aeadCtx,
    workArea,
    outBuf,
    &outputSize,
    computedTagBuffer));

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Total *pOutLength have an upper bound of inLength ")
  *pOutLength += outputSize;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  /* Prepare the reference tag. For buffer-objects with DMA, this will import the tag to a CPU buffer before comparison. */
  const uint8_t *pReferenceTag;
  mcuxClBuffer_inputBufferToCPU(pTag, 0u, workArea->cpuWa.tagBuffer, &pReferenceTag, tagLength);
  MCUX_CSSL_DI_RECORD(referenceTag, pReferenceTag); /* Will be balanced in mcuxClMemory_compare_dpasecure_int() */

  /* Compare authentication tags */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_compare_dpasecure_int));
  MCUX_CSSL_FP_FUNCTION_CALL(compareStatus, mcuxClMemory_compare_dpasecure_int(session, pReferenceTag, pComputedTag, tagLength));
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
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_cleanupOnOneshotExit));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAeadModes_cleanupOnOneshotExit(session, key, cpuWaSizeInWords + ctxSizeInWords));
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAeadModes_decrypt, retCode);
}
