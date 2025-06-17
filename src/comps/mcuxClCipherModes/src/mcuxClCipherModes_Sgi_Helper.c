/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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

#include <mcuxClToolchain.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <internal/mcuxClSgi_Sfr_Ctrl.h>

#include <internal/mcuxClDma_Utils_Sgi.h>
#include <internal/mcuxClDma_Utils.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClCipher_Internal.h>
#include <mcuxClAes.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Cleanup.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <mcuxClMemory.h>
#include <internal/mcuxClSgi_Drv.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClBuffer.h>

#include <internal/mcuxClAes_Internal_Functions.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_copyOut_toPtr, mcuxClSgi_copyOut_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_copyOut_toPtr(
  mcuxClSession_Handle_t session,
  void* pWa,
  mcuxCl_Buffer_t outBuf,
  uint32_t offset,
  uint32_t byteLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_copyOut_toPtr);
  mcuxClCipherModes_WorkArea_t* pWaCipher = mcuxClCipherModes_castToCipherModesWorkArea(pWa);

  if(MCUXCLAES_BLOCK_SIZE != byteLength)
  {
    /* If length is not full block size, copy from SGI into a temporary buffer to avoid byte-wise access to SGI. */
    uint8_t* outData = pWaCipher->sgiWa.paddingBuff;
    MCUX_CSSL_DI_RECORD(store128BitBlockDI /* Not used */, (uint32_t)outData + MCUXCLAES_BLOCK_SIZE);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock(MCUXCLSGI_DRV_DATOUT_OFFSET, outData));
    MCUX_CSSL_DI_RECORD(bufferWriteDI, (uint32_t)outData);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(outBuf, offset, outData, byteLength));
  }
  else
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock_buffer(session, MCUXCLSGI_DRV_DATOUT_OFFSET, outBuf, offset));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_copyOut_toPtr,
                                MCUX_CSSL_FP_CONDITIONAL(MCUXCLAES_BLOCK_SIZE != byteLength,
                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock),
                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write) ),
                                MCUX_CSSL_FP_CONDITIONAL(MCUXCLAES_BLOCK_SIZE == byteLength,
                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock_buffer) )
                                );
}




/*** Functions to handle the IV ***/

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_No_IV, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_No_IV(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_No_IV);

  pWa->pIV = NULL;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_No_IV);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_IV, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_IV);

  MCUX_CSSL_DI_RECORD(sgiLoadBuffer, ((uint32_t)pIv) + (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN1_OFFSET) + 16u);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock_buffer(MCUXCLSGI_DRV_DATIN1_OFFSET, pIv, 0u));  /* load the IV in DATIN1 */

  /* Store the needed register of the IV s.t. intermediate IVs can be re-loaded after crypt operations */
  pWa->pIV = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN1_OFFSET);
  pWa->ctrSize = MCUXCLAES_BLOCK_SIZE;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_IV,
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock_buffer));
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_checkIvLen_noIv, mcuxClCipherModes_CheckIvLength_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_checkIvLen_noIv(
  mcuxClSession_Handle_t session,
  uint32_t ivLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_checkIvLen_noIv);

  if(0u == ivLength)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_checkIvLen_noIv);
  }

  MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_checkIvLen, mcuxClCipherModes_CheckIvLength_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_checkIvLen(
  mcuxClSession_Handle_t session,
  uint32_t ivLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_checkIvLen);

  if(MCUXCLAES_BLOCK_SIZE == ivLength)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_checkIvLen);
  }

  MCUXCLSESSION_ERROR(session, MCUXCLCIPHER_STATUS_INVALID_INPUT);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_IV_AutoMode_Cbc_Dec, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_AutoMode_Cbc_Dec(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_IV_AutoMode_Cbc_Dec);

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  /* Copy IV to SGI DATIN2 with DMA, as needed by SGI AUTO mode.
     Note that this is not according to SGI spec. In spec it states to first enable
     SGI AUTO mode with cmd=CBC and direction=decrypt before loading IV to DATIN0.
     As we know SGI AUTO mode propagates the IV internally to DATIN2 (from DATIN0),
     we just write it to DATIN2 directly.
     This mitigates some issues when disabling SGI AUTO mode for the single-block case,
     where the IV in DATIN0 is overwritten once AUTO mode is disabled. In DATIN2 the IV
     is kept, hence it allows us for a more consistent SW behaviour for multi-block and
     single-block handling.
  */
  mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN2_OFFSET, MCUXCLBUFFER_GET(pIv));
  mcuxClDma_Utils_startTransferOneBlock(inputChannel);

  /* Store the needed register of the IV s.t. intermediate IVs can be re-loaded after crypt operations */
  pWa->pIV = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN2_OFFSET);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_IV_AutoMode_Cbc_Dec);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_IV_to_DATOUT_DMA, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_to_DATOUT_DMA(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_IV_to_DATOUT_DMA);

  /* Copy IV to SGI DATOUT with DMA */
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATOUT_OFFSET, MCUXCLBUFFER_GET(pIv));
  mcuxClDma_Utils_startTransferOneBlock(inputChannel);

  /* Store the needed register of the IV s.t. intermediate IVs can be re-loaded after crypt operations */
  pWa->pIV = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_IV_to_DATOUT_DMA);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_IV_AutoMode_Ctr, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_AutoMode_Ctr(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_IV_AutoMode_Ctr);

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);

  /* Known limitation: Configure and start the SGI to AUTO mode CTR *before* loading the IV to DATIN0 */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_CTR_128));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(pWa->sgiWa.sgiCtrlKey | MCUXCLSGI_DRV_CTRL_NO_UP));

  /* Copy IV to SGI DATIN0 with DMA */
  mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLBUFFER_GET(pIv));
  mcuxClDma_Utils_startTransferOneBlock(inputChannel);

  /* Use DATA register that is used to store the current IV. */
  pWa->pIV = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN2_OFFSET);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_Drv_waitForChannelDone));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_Drv_waitForChannelDone(session, inputChannel));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_IV_AutoMode_Ctr);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_loadMaskedKeyAndIvtoSgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_loadMaskedKeyAndIvtoSgi(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_Context_Aes_Sgi_t * pCtx,
  mcuxClCipherModes_WorkArea_t * pWa,
  uint32_t inLength,
  mcuxClKey_KeyChecksum_t** pKeyChecksum
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_loadMaskedKeyAndIvtoSgi);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("pCtx->common.blockBufferUsed can't be larger than MCUXCLAES_BLOCK_SIZE")
  if((MCUXCLAES_BLOCK_SIZE - pCtx->common.blockBufferUsed) <= inLength)
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadMaskedKeyFromCtx_Sgi));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadMaskedKeyFromCtx_Sgi(session, &(pCtx->keyContext), &pWa->sgiWa, MCUXCLSGI_DRV_KEY0_OFFSET, MCUXCLAES_MASKED_KEY_SIZE));
    if(pKeyChecksum != NULL)
    {
      *pKeyChecksum = &pCtx->keyContext.keyChecksums;
    }
    MCUXCLBUFFER_INIT_RO(ivBuff, session, pCtx->ivState, MCUXCLAES_BLOCK_SIZE_IN_WORDS);
    MCUX_CSSL_FP_EXPECT(pCtx->protectionToken_setupIV);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(pCtx->setupIV(session, pWa, ivBuff));
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_loadMaskedKeyAndIvtoSgi);
}
