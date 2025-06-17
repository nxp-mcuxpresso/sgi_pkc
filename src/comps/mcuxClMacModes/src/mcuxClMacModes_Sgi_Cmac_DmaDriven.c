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

#include <mcuxClToolchain.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClCore_Macros.h>
#include <mcuxClMac.h>
#include <mcuxClMacModes_MemoryConsumption.h>
#include <internal/mcuxClMacModes_Common_Wa.h>
#include <internal/mcuxClMacModes_Sgi_Functions.h>
#include <internal/mcuxClMacModes_Sgi_Types.h>
#include <internal/mcuxClMacModes_Sgi_Cmac.h>
#include <internal/mcuxClMacModes_Sgi_Algorithms.h>

#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClAes.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <mcuxClDma_Types.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Utils.h>
#include <internal/mcuxClDma_Utils_Sgi.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClDma_Resource.h>
#include <mcuxClBuffer.h>


/* Shared CMAC DMA-driven helper */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_handleLastBlock_cmac_oneshot, mcuxClMacModes_handleLastBlock_oneshot_t)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_handleLastBlock_cmac_oneshot(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t * pWa,
  mcuxClMacModes_Algorithm_t pAlgo,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inOffset,
  uint32_t totalInputLength,
  uint32_t remainingBytes
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_handleLastBlock_cmac_oneshot);

  uint32_t *pSubKey = pWa->algoWa.subKeys[0]; /* for full blocks get subKey1 */

  /* Apply padding to the last block if needed, while SGI is busy */
  uint32_t padOutLen = 0u;

  MCUX_CSSL_FP_EXPECT(pAlgo->protectionToken_addPadding);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pAlgo->addPadding(
    session,
    MCUXCLAES_BLOCK_SIZE,
    pIn,
    inOffset,
    remainingBytes,
    totalInputLength,
    pWa->sgiWa.paddingBuff,
    &padOutLen));

  /* AUTO mode limitation: SGI will only de-assert the busy flag once the (CBC-)MAC output is read.
     Access the DATOUT once to trigger SGI finish. Otherwise, SGI will be stuck and the last block
     cannot be handled. */
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 0u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 4u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 8u);
  (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 12u);

  /* Known bug in SGI AUTO mode: if AUTO_MODE.CMD is not reset to 0 here, subsequent SGI operations will not work.
     Workaround: wait for SGI and reset AUTO_MODE to 0. To be removed in CLNS-7392 once fixed in HW. */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait()); /* Known limitation: wait for SGI busy flag to be de-asserted before overwriting AUTO mode CMD */
  mcuxClSgi_Drv_resetAutoMode();

  /* Load the last block to DATIN0 */
  if(MCUXCLAES_BLOCK_SIZE == padOutLen)
  {
    /* Padding was added - Copy padded input to SGI */
    MCUX_CSSL_DI_RECORD(sgiLoad, ((uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET)) + ((uint32_t)pWa->sgiWa.paddingBuff) + 16u);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, pWa->sgiWa.paddingBuff));
    /* Use subKey2 because padding was added */
    pSubKey = pWa->algoWa.subKeys[1];
  }
  else
  {
    mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
    MCUXCLBUFFER_DERIVE_RO(pInWithOffset, pIn, inOffset);

    /* No padding needed - Copy last input block to SGI */
    mcuxClDma_Utils_configureSgiInputChannel(session, MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLBUFFER_GET(pInWithOffset));
    mcuxClDma_Utils_startTransferOneBlock(inputChannel);

    /* Wait for data copy to finish and check for errors */
    mcuxClDma_Drv_waitForChannelDone(session, inputChannel);
  }

  /* XOR the last block with the chosen subkey, use SGI XorOnWrite feature */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableXorWrite));
  MCUX_CSSL_FP_FUNCTION_CALL(retXorWrite, mcuxClSgi_Drv_enableXorWrite());
  (void)retXorWrite;
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setByteOrder));
  MCUX_CSSL_FP_FUNCTION_CALL(retSetByteOrder, mcuxClSgi_Drv_setByteOrder((uint32_t)MCUXCLSGI_DRV_BYTE_ORDER_BE));
  (void)retSetByteOrder; /* subkeys are in big-endian, so we need to switch the SGI to BE (for the copy only) */
  MCUX_CSSL_DI_RECORD(sgiLoad, ((uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET)) + ((uint32_t)pSubKey) + 16u);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, (uint8_t *)pSubKey));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableXorWrite));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableXorWrite());
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setByteOrder));
  MCUX_CSSL_FP_FUNCTION_CALL(retSetByteOrder2, mcuxClSgi_Drv_setByteOrder((uint32_t)MCUXCLSGI_DRV_BYTE_ORDER_LE));
  (void)retSetByteOrder2;

  /* Perform encryption of the last block */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
    pWa->sgiWa.sgiCtrlKey                     |
    MCUXCLSGI_DRV_CTRL_ENC                     |
    MCUXCLSGI_DRV_CTRL_END_UP                  |
    MCUXCLSGI_DRV_CTRL_INSEL_DATIN0_XOR_DATOUT | /* IV stored in DATOUT, IV ^ lastblock ^ subkey */
    MCUXCLSGI_DRV_CTRL_OUTSEL_RES));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMacModes_handleLastBlock_cmac_oneshot);
}
