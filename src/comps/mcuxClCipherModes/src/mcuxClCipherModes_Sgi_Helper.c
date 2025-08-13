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

#include <internal/mcuxClCipher_Internal.h>
#include <mcuxClAes.h>
#include <internal/mcuxClCipherModes_Common.h>
#include <internal/mcuxClCipherModes_Sgi_Cleanup.h>
#include <internal/mcuxClCipherModes_Sgi_Helper.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClBuffer.h>
#include <internal/mcuxClDma_Resource.h>
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
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock(MCUXCLSGI_DRV_DATOUT_OFFSET, outBuf + offset));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_copyOut_toPtr,
                                MCUX_CSSL_FP_CONDITIONAL(MCUXCLAES_BLOCK_SIZE != byteLength,
                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock),
                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write) ),
                                MCUX_CSSL_FP_CONDITIONAL(MCUXCLAES_BLOCK_SIZE == byteLength,
                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock) )
                                );
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

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_requestDmaChannelsAndConfigureJobContext)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_requestDmaChannelsAndConfigureJobContext(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxClSession_HwInterruptHandler_t callbackFunction,
  uint32_t protectionToken_callbackFunction
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_requestDmaChannelsAndConfigureJobContext);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_request(
    session,
    mcuxClSession_getDmaOutputChannel(session),
    callbackFunction,
    protectionToken_callbackFunction
  ));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_request(
    session,
    mcuxClSession_getDmaInputChannel(session),
    callbackFunction,
    protectionToken_callbackFunction
  ));

  mcuxClSession_job_setClWorkarea(session, (void*) pWa);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCipherModes_requestDmaChannelsAndConfigureJobContext,
    2U * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_request)
  );
}

