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

#include <mcuxClCore_Toolchain.h>
#include <mcuxClToolchain.h>

#include <mcuxClAes.h>
#include <mcuxClCipherModes_Modes.h>
#include <mcuxClKey.h>
#include <mcuxClKey_Types.h>
#include <mcuxClMac.h>
#include <mcuxClSession.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClCipherModes_Sgi_Algorithms.h>
#include <internal/mcuxClMacModes_Common_Constants.h>
#include <internal/mcuxClMacModes_Common_Memory.h>
#include <internal/mcuxClMacModes_Common_Types.h>
#include <internal/mcuxClMacModes_Common_Wa.h>
#include <internal/mcuxClMacModes_Sgi_Algorithms.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>
#include <internal/mcuxClMacModes_Sgi_Functions.h>
#include <internal/mcuxClMacModes_Sgi_Gmac.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClPrng_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>


/* GMAC */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_GMAC =
{
  .init = mcuxClMacModes_initGMAC,
  .protectionToken_init = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_initGMAC),
  .update = mcuxClMacModes_updateGMAC,
  .protectionToken_update = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_updateGMAC),
  .copyOut = mcuxClMacModes_CopyOutNormal,
  .protectionToken_copyOut = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_CopyOutNormal),
  .addPadding = NULL
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_loadZeroPaddingBlock)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_loadZeroPaddingBlock(
  mcuxCl_InputBuffer_t pInput,
  uint32_t inputOffset,
  uint8_t *tmpBuffer,
  size_t size);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_generateHKey)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_generateHKey(
  uint32_t keySgiCtrl);

/**
 * Internal function that computes J0
 *
 * Data Integrity: Expunge(nonceLength)
 *
 * @param[in]  pWa           Pointer macModes workarea
 * @param[in]  pContext      Pointer to the context
 * @param[in]  pNonce        Input buffer which contains the nonce
 * @param[in]  nonceLength   Length of the nonce in the @p pNonce buffer
 * @param[out] pJ0           Pointer to store the calculated J0
 * @param[in]  pTmp          Pointer to some temporary memory
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_computeJ0)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_computeJ0(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *pWa,
  mcuxClMacModes_Context_t *pContext,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint8_t *pJ0,
  uint8_t *pTmp);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_CTR_oneBlock, mcuxClMacModes_ComputePreTagFunc_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_CTR_oneBlock(
  mcuxCl_InputBuffer_t pInput,
  uint32_t inputOffset,
  uint32_t inLength,
  uint32_t operation);

/* Engines */


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_initGMAC, mcuxClMacModes_InitFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_initGMAC(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t * workArea,
  mcuxClMacModes_Context_t * const pContext
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_initGMAC);

  pContext->totalInput = 0u;
  pContext->blockBufferUsed = 0u;

  /* Assumes AES key already loaded - non blocking. H-Key will be in Key2 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_generateHKey));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_generateHKey(pContext->keyContext.sgiCtrlKey));

  /* Obtain gmac mode descriptor from macModes context */
  mcuxClMacModes_GmacModeDescriptor_t *gmacModeFields = (mcuxClMacModes_GmacModeDescriptor_t *)pContext->common.pMode->pCustom;

  /* Check ivLength - SREQI_AEAD_11, SREQI_MAC_18 */
  if(0u == gmacModeFields->ivLength)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLMAC_STATUS_INVALID_PARAM);
  }

  /* Ensure that ivLength is not corrupted before J0 is computed - SREQI_AEAD_11, SREQI_MAC_18  */
  MCUX_CSSL_DI_RECORD(ivLengthProtection, gmacModeFields->ivLength);

  /* Create J0 while SGI is busy */
  uint8_t *pTmp = (uint8_t *)pContext->blockBuffer; /* Use blockbuffer as temp buffer for J0 generation */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_computeJ0));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_computeJ0(
    session,
    workArea,
    pContext,
    gmacModeFields->pIv,
    gmacModeFields->ivLength,
    (uint8_t *)pContext->counter0,
    pTmp));

  // TODO CLNS-17176: Use mcuxClAes_storeSubKeyInCtx_Sgi
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_storeMaskedKeyInCtx_Sgi));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_storeMaskedKeyInCtx_Sgi(
    session,
    NULL,
    &(pContext->HkeyContext),
    NULL,
    MCUXCLSGI_DRV_KEY2_OFFSET,
    MCUXCLAES_GCM_H_KEY_SIZE
  ));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_initGMAC);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_updateGMAC, mcuxClMacModes_UpdateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_updateGMAC(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *workArea,
  mcuxClMacModes_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  uint32_t * pProcessedBytes UNUSED_PARAM
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_updateGMAC);

  if(0u != inLength)
  {
    pContext->dataProcessed = MCUXCLMACMODES_TRUE;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("totalInput has an upper bound of inLength")
    pContext->totalInput += inLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    /* Load the H-key */
    // TODO CLNS-17176: Use mcuxClAes_loadSubKeyFromCtx_Sgi
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session,
                                                                     &(pContext->HkeyContext),
                                                                     NULL,
                                                                     MCUXCLSGI_DRV_KEY2_OFFSET,
                                                                     MCUXCLAES_GCM_H_KEY_SIZE));

    uint32_t operation =  MCUXCLSGI_DRV_CTRL_END_UP |
                          MCUXCLSGI_DRV_CTRL_GFMUL |
                          MCUXCLSGI_DRV_CTRL_INSEL_DATIN0 |
                          MCUXCLSGI_DRV_CTRL_OUTSEL_RES |
                          MCUXCLSGI_DRV_CTRL_INKEYSEL(MCUXCLSGI_DRV_KEY2_INDEX) |
                          MCUXCLSGI_DRV_CTRL_ENC;

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_process_preTag_calculation));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_process_preTag_calculation(
      session,
      workArea,
      pContext,
      pIn,
      inLength,
      operation));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_updateGMAC, MCUXCLMAC_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_finalizeDataGMAC)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_finalizeDataGMAC(
    mcuxClSession_Handle_t session,
    mcuxClMacModes_WorkArea_t *workArea,
    mcuxClMacModes_Context_t *const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_finalizeDataGMAC);

  /* Copy (masked) preTag to DATOUT */
  uint32_t *pDst_sgiDatout = (uint32_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
  const uint32_t *pSrc_maskedPreTag = (const uint32_t *)pContext->maskedPreTag;
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pDst_sgiDatout);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pSrc_maskedPreTag);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
    pDst_sgiDatout,
    pSrc_maskedPreTag,
    16u,
    pContext->keyContext.keySeed));

  /* If we have some remaining data in buffer then add zero padding and calc pretag */
  if(0u != pContext->blockBufferUsed)
  {
    uint32_t operation = MCUXCLSGI_DRV_CTRL_END_UP |
                          MCUXCLSGI_DRV_CTRL_GFMUL |
                          MCUXCLSGI_DRV_CTRL_INSEL_DATIN0 |
                          MCUXCLSGI_DRV_CTRL_OUTSEL_RES |
                          MCUXCLSGI_DRV_CTRL_INKEYSEL(MCUXCLSGI_DRV_KEY2_INDEX) |
                          MCUXCLSGI_DRV_CTRL_ENC;

    /* Process remaining adata and create pretag */
    MCUXCLBUFFER_INIT_RO(blockBuf, NULL, (uint8_t *)pContext->blockBuffer, MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_loadZeroPaddingBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_loadZeroPaddingBlock(blockBuf, 0u, workArea->sgiWa.paddingBuff, pContext->blockBufferUsed));

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      workArea,
      pContext,
      NULL,
      0u,
      0u,
      pContext->keyContext.keySeed,
      operation,
      mcuxClMacModes_finalizeEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

    // Copy out result
    const uint32_t *pSrc_sgiDatout = (const uint32_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
    uint32_t *pDst_maskedPreTag = (uint32_t *)pContext->maskedPreTag;
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pSrc_sgiDatout);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pDst_maskedPreTag);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
      pDst_maskedPreTag,
      pSrc_sgiDatout,
      16u,
      pContext->keyContext.keySeed));

    pContext->blockBufferUsed = 0u;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_finalizeDataGMAC);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_finalizeSizesGMAC)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_finalizeSizesGMAC(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t* workArea,
  mcuxClMacModes_Context_t* const pContext,
  uint32_t payloadLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_finalizeSizesGMAC);

  uint32_t operation = MCUXCLSGI_DRV_CTRL_END_UP |
                        MCUXCLSGI_DRV_CTRL_GFMUL |
                        MCUXCLSGI_DRV_CTRL_INSEL_DATIN0 |
                        MCUXCLSGI_DRV_CTRL_OUTSEL_RES |
                        MCUXCLSGI_DRV_CTRL_INKEYSEL(MCUXCLSGI_DRV_KEY2_INDEX) |
                        MCUXCLSGI_DRV_CTRL_ENC;

  /* Hash the insize (= adataSize, according to standard) and payLoadLength, use pTmp again */
  uint8_t* pTmp = workArea->sgiWa.paddingBuff; /* Use paddingBuff as temp buffer */

  /* DI balancing for tmp clearing */
  MCUX_CSSL_DI_RECORD(tmp_clear, (uint32_t)pTmp);
  MCUX_CSSL_DI_RECORD(tmp_clear, MCUXCLAES_BLOCK_SIZE);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *) pTmp, MCUXCLAES_BLOCK_SIZE));

  uint64_t aadLengthInBits = ((uint64_t)(pContext->totalInput) - (uint64_t)payloadLength) * 8u;
  aadLengthInBits = mcuxCl_Core_Swap64(aadLengthInBits);

  MCUX_CSSL_DI_RECORD(tmp_cpy, (uint32_t)&pTmp[0u]);
  MCUX_CSSL_DI_RECORD(tmp_cpy, (uint32_t)&aadLengthInBits);
  MCUX_CSSL_DI_RECORD(tmp_cpy, 8u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(&pTmp[0u], (uint8_t*)&aadLengthInBits, 8u));

  if(0u != payloadLength)
  {
    uint64_t payloadLengthInBits = (uint64_t)payloadLength * 8u;
    payloadLengthInBits = mcuxCl_Core_Swap64(payloadLengthInBits);

    MCUX_CSSL_DI_RECORD(tmp_cpy, (uint32_t)&pTmp[8u]);
    MCUX_CSSL_DI_RECORD(tmp_cpy, (uint32_t)&payloadLengthInBits);
    MCUX_CSSL_DI_RECORD(tmp_cpy, 8u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(&pTmp[8u], (uint8_t*)&payloadLengthInBits, 8u));
  }

  /* Record load input */
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)pTmp);
  MCUX_CSSL_DI_RECORD(sgiLoad, 16u);

  /* Copy input to SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, pTmp));

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
    session,
    workArea,
    pContext,
    NULL,
    0u,
    0u,
    pContext->keyContext.keySeed,
    operation,
    mcuxClMacModes_finalizeEngine,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  /* Perform a masked copy of DATOUT to DATIN1 (via maskedPreTag buffer) */
  const uint32_t *pSrc_sgiDatout = (const uint32_t *)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
  uint32_t *pMaskedCopyTgt = (uint32_t *)pContext->maskedPreTag;
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pMaskedCopyTgt);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pSrc_sgiDatout);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
    pMaskedCopyTgt,
    pSrc_sgiDatout,
    16u,
    pContext->keyContext.keySeed));

  uint32_t *pDst_sgiDatin1 = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN1_OFFSET);
  const uint32_t *pSrc_maskedPreTag = (const uint32_t *)pContext->maskedPreTag;
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, pDst_sgiDatin1);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, (uint32_t)pSrc_maskedPreTag);
  MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked, 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(
    pDst_sgiDatin1,
    pSrc_maskedPreTag,
    16u,
    pContext->keyContext.keySeed));

  /* Encrypt the preTag with counter0 to get the final tag within SGI DATOUT */
  operation = MCUXCLSGI_DRV_CTRL_END_UP |
              MCUXCLSGI_DRV_CTRL_ENC |
              MCUXCLSGI_DRV_CTRL_INSEL_DATIN0 |
              MCUXCLSGI_DRV_CTRL_OUTSEL_RES_XOR_DATIN1 |
              workArea->sgiWa.sgiCtrlKey;

  MCUXCLBUFFER_INIT_RO(pIVBuf, NULL, (uint8_t *)pContext->counter0, MCUXCLAES_BLOCK_SIZE);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
    session,
    workArea,
    pContext,
    pIVBuf,
    0u,
    MCUXCLAES_BLOCK_SIZE,
    pContext->keyContext.keySeed,
    operation,
    mcuxClMacModes_CTR_oneBlock,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_CTR_oneBlock)));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_finalizeSizesGMAC);
}



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_loadZeroPaddingBlock)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_loadZeroPaddingBlock(
  mcuxCl_InputBuffer_t pInput,
  uint32_t inputOffset,
  uint8_t * tmpBuffer,
  size_t size)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_loadZeroPaddingBlock);

  /* DI balancing for tmp clearing and buffer read */
  MCUX_CSSL_DI_RECORD(tmp_clear, (uint32_t) &tmpBuffer[size]);
  MCUX_CSSL_DI_RECORD(tmp_clear, MCUXCLAES_BLOCK_SIZE - size);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, pInput);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, inputOffset);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, tmpBuffer);
  MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, size);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_secure));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_secure(pInput, inputOffset, tmpBuffer, size));

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("size has an upper bound of MCUXCLAES_BLOCK_SIZE")
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *) &tmpBuffer[size], MCUXCLAES_BLOCK_SIZE - size));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

  //Copy input to SGI
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)tmpBuffer);
  MCUX_CSSL_DI_RECORD(sgiLoad, 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, tmpBuffer));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_loadZeroPaddingBlock);
}

/* This function will generate an H-key in hardware with the given master key context.
 * This function will not perform a call to mcuxClSgi_Drv_wait, so the caller must ensure
 * the operation finished before accessing the SGI again.
 *
 * TODO CLNS-17176: the H-key is an internal key/subkey and shall always be in KEY2
 * The resulting H-key will be stored in Key2.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_generateHKey)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_generateHKey(
  uint32_t keySgiCtrl)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_generateHKey);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 0U, 0U));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 4U, 0U));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 8U, 0U));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 12U, 0U));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableOutputToKey));
  MCUX_CSSL_FP_FUNCTION_CALL(ret, mcuxClSgi_Drv_enableOutputToKey(MCUXCLSGI_DRV_KEY2_INDEX));
  (void)ret;

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
    MCUXCLSGI_DRV_CTRL_END_UP        |
    MCUXCLSGI_DRV_CTRL_ENC           |
    MCUXCLSGI_DRV_CTRL_INSEL_DATIN0  |
    MCUXCLSGI_DRV_CTRL_OUTSEL_RES    |
    keySgiCtrl));

  /* Don't wait and do some other operation while SGI is creating H key */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_generateHKey,
    (4U * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_loadWord))
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_computeJ0)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_computeJ0(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t * pWa,
  mcuxClMacModes_Context_t * pContext,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint8_t * pJ0,
  uint8_t * pTmp /* temporary buffer needed to calculate J0 */)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_computeJ0);

  /* For J0 clearing */
  MCUX_CSSL_DI_RECORD(J0_clear, (uint32_t)pJ0);
  MCUX_CSSL_DI_RECORD(J0_clear, MCUXCLAES_BLOCK_SIZE);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *) pJ0, MCUXCLAES_BLOCK_SIZE));

  if(12u == nonceLength)
  {
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, pNonce);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, pJ0);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read_secure, 12u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_secure));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_secure(pNonce, 0u, pJ0, 12u));

    pJ0[15] = 0x01u;

    /* wait for H-key to be fully generated */
    mcuxClSgi_Drv_wait();
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableOutputToKey));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableOutputToKey());
  }
  else
  {
    /* Use Ghash - H-key will be in KEY2;
     * Wait for SGI as HKEY might not yet be generated, and disable outputToKey */
    mcuxClSgi_Drv_wait();
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableOutputToKey));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableOutputToKey());

    /* GHASH( Nonce | 0 ) */
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET));
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)pJ0);
    MCUX_CSSL_DI_RECORD(sgiLoad, 16u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATOUT_OFFSET, pJ0)); /* load IV */

    uint32_t operation = MCUXCLSGI_DRV_CTRL_END_UP |
                       MCUXCLSGI_DRV_CTRL_GFMUL |
                       MCUXCLSGI_DRV_CTRL_INSEL_DATIN0 |
                       MCUXCLSGI_DRV_CTRL_OUTSEL_RES |
                       MCUXCLSGI_DRV_CTRL_INKEYSEL(MCUXCLSGI_DRV_KEY2_INDEX) |
                       MCUXCLSGI_DRV_CTRL_ENC;

    uint32_t nonceOffset = 0u;
    uint32_t noOfBytesToProcess = nonceLength;
    uint32_t nonceLenInBlocks = nonceLength / MCUXCLAES_BLOCK_SIZE;
    if(0u < nonceLenInBlocks)
    {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
        session,
        pWa,
        pContext,
        pNonce,
        0u,
        nonceLenInBlocks * MCUXCLAES_BLOCK_SIZE,
        0u,
        operation,
        mcuxClMacModes_updateEngine,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_updateEngine)));

      nonceOffset += nonceLenInBlocks * MCUXCLAES_BLOCK_SIZE;
      noOfBytesToProcess -= nonceLenInBlocks * MCUXCLAES_BLOCK_SIZE;
    }

    if(0u != noOfBytesToProcess)
    {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_loadZeroPaddingBlock));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_loadZeroPaddingBlock(
        pNonce,
        nonceOffset,
        pWa->sgiWa.paddingBuff,
        noOfBytesToProcess));

      MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
        session,
        pWa,
        pContext,
        NULL,
        0u,
        0u,
        0u,
        operation,
        mcuxClMacModes_finalizeEngine,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
    }

    /* GHASH( 0 | nonceLength ) */
    uint32_t nonceLenInBits = mcuxCl_Core_Swap32(nonceLength * 8u);

    /* For tmp clearing */
    MCUX_CSSL_DI_RECORD(tmp_clear, (uint32_t)pTmp);
    MCUX_CSSL_DI_RECORD(tmp_clear, MCUXCLAES_BLOCK_SIZE);

    MCUX_CSSL_DI_RECORD(tmp_cpy, (uint32_t)&pTmp[12u]);
    MCUX_CSSL_DI_RECORD(tmp_cpy, (uint32_t)&nonceLenInBits);
    MCUX_CSSL_DI_RECORD(tmp_cpy, sizeof(uint32_t));

    /* Use blockBuffer as temp buffer */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int((uint8_t *) pTmp, MCUXCLAES_BLOCK_SIZE));
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(&pTmp[12], (uint8_t *)&nonceLenInBits, sizeof(uint32_t)));

    /* Record load input */
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
    MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)pTmp);
    MCUX_CSSL_DI_RECORD(sgiLoad, 16u);

    /* Copy input to SGI */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, pTmp));

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("this null pointer is unused in this function ")
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_engine));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMacModes_engine(
      session,
      pWa,
      pContext,
      NULL,
      0u,
      0u,
      0u,
      operation,
      mcuxClMacModes_finalizeEngine,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_finalizeEngine)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

    // Copy out result
    MCUX_CSSL_DI_RECORD(sgiStore, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET));
    MCUX_CSSL_DI_RECORD(sgiStore, (uint32_t)pJ0);
    MCUX_CSSL_DI_RECORD(sgiStore, 16u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock(MCUXCLSGI_DRV_DATOUT_OFFSET, pJ0));
  }

  /* Ensure that ivLength is not corrupted before J0 is computed - SREQI_AEAD_11, SREQI_MAC_18  */
  MCUX_CSSL_DI_EXPUNGE(ivLengthProtection, nonceLength);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_computeJ0);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_CTR_oneBlock, mcuxClMacModes_ComputePreTagFunc_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_CTR_oneBlock(
  mcuxCl_InputBuffer_t pInput,
  uint32_t inputOffset,
  uint32_t inLength UNUSED_PARAM,
  uint32_t operation)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_CTR_oneBlock);

  /* Record sgi processing blocks */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
  MCUX_CSSL_FP_FUNCTION_CALL(currCount, mcuxClSgi_Drv_getCount());
  MCUX_CSSL_ANALYSIS_START_PATTERN_SC_INTEGER_OVERFLOW()
  const uint32_t sgiCount = 1u  + currCount;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SC_INTEGER_OVERFLOW()
  const uint32_t sgiCountOverflow = sgiCount & 0xFFFF0000u; // since SGI_COUNT is 16-bit register, save the possibly overflowed value and use it in DI_EXPUNGE at the end
  MCUX_CSSL_DI_RECORD(sgiCount, sgiCount);

  /* Record sgi load input */
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
  MCUX_CSSL_DI_RECORD(sgiLoad, (uint32_t)pInput);
  MCUX_CSSL_DI_RECORD(sgiLoad, inputOffset);
  MCUX_CSSL_DI_RECORD(sgiLoad, 16u);

  //Copy IV to SGI
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, pInput + inputOffset));

  //start calc
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(operation));

  //wait for finish
  mcuxClSgi_Drv_wait();

  /* Expunge the current value of the SGI COUNT plus the possibly overflowed value for DI protection.
     The sum is equal to the SGI COUNT in the beginning plus one. */

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_getCount));
  MCUX_CSSL_FP_FUNCTION_CALL(currCount2, mcuxClSgi_Drv_getCount());
  MCUX_CSSL_ANALYSIS_START_PATTERN_SC_INTEGER_OVERFLOW()
  uint32_t endCount = sgiCountOverflow + currCount2;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SC_INTEGER_OVERFLOW()
  MCUX_CSSL_DI_EXPUNGE(sgiCount, endCount);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_CTR_oneBlock);
}
