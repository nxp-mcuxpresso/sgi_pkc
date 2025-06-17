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
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Sfr.h>
#include <mcuxClDma_Types.h>
#include <internal/mcuxClDma_Utils.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment)
void mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(
  const uint8_t *pAddr,
  uint16_t *pOffset,
  uint16_t *pSize,
  uint32_t size)
{
  /* Check alignment of address to configure the DMA offset that is used after each R/W access:
       If quad word aligned, set offset and size to values corresponding to 16-byte access,
       If double word aligned, set offset and size to values corresponding to 8-byte access,
       If word aligned, set offset and size to values corresponding to 4-byte access,
       if half-word aligned, set offset and size to values corresponding to 2-byte access,
       if byte aligned, set offset and size to values corresponding to 1-byte access.
  */

  if((0uL == ((uint32_t)pAddr & 0x0Fu)) && (0u == (size & 0xFu)))
  {
    /* address is quad word aligned */
    *pOffset = MCUXCLDMA_DRV_OFFSET_INCR_16_BYTE;
    *pSize = MCUXCLDMA_SFR_TCD_ATTR_SSIZE_DSIZE_16_BYTE;
  }
  else if((0uL == ((uint32_t)pAddr & 0x07u)) && (0u == (size & 0x7u)))
  {
    /* address is double word aligned */
    *pOffset = MCUXCLDMA_DRV_OFFSET_INCR_8_BYTE;
    *pSize = MCUXCLDMA_SFR_TCD_ATTR_SSIZE_DSIZE_8_BYTE;
  }
  else if(0uL == ((uint32_t)pAddr & 0x03u) && (0u == (size & 0x3u)))
  {
    /* address is word aligned */
    *pOffset = MCUXCLDMA_DRV_OFFSET_INCR_4_BYTE;
    *pSize = MCUXCLDMA_SFR_TCD_ATTR_SSIZE_DSIZE_4_BYTE;
  }
  else if(0uL == ((uint32_t)pAddr & 0x01u) && (0u == (size & 0x1u)))
  {
    /* address is half-word aligned */
    *pOffset = MCUXCLDMA_DRV_OFFSET_INCR_2_BYTE;
    *pSize = MCUXCLDMA_SFR_TCD_ATTR_SSIZE_DSIZE_2_BYTE;
  }
  else
  {
    /* address is byte aligned */
    *pOffset = MCUXCLDMA_DRV_OFFSET_INCR_1_BYTE;
    *pSize = MCUXCLDMA_SFR_TCD_ATTR_SSIZE_DSIZE_1_BYTE;
  }
}

/** Configure the given DMA channel to transfer a specific amount of data from pSrc to pDst */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Utils_configureDataTransfer)
void mcuxClDma_Utils_configureDataTransfer(
  mcuxClSession_Channel_t channel,
  const uint8_t *pSrc,
  uint8_t *pDst,
  uint32_t length)
{
  /* If the requested length is not a multiple of the word size - perform byte-wise access/transfer */
  uint16_t srcOffset = 0u;
  uint16_t dstOffset = 0u;
  uint16_t srcSize = 0u;
  uint16_t dstSize = 0u;

  /* get most performant access sizes based on address alignments and total transfer size */
  mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(pSrc, &srcOffset, &srcSize, length);
  mcuxClDma_Utils_getTCDOffsetAndSizeFromAlignment(pDst, &dstOffset, &dstSize, length);

  /*
   * Write the TCD of the channel
   */
  mcuxClDma_Drv_writeMajorLoopCounts(channel, 1u); /* Transfer all bytes in single iteration, default setting */
  mcuxClDma_Drv_writeTransferSize(channel, length);
  mcuxClDma_Drv_writeSrcAddress(channel, pSrc);
  mcuxClDma_Drv_writeSrcOffset(channel, srcOffset);
  mcuxClDma_Drv_writeDstAddress(channel, pDst);
  mcuxClDma_Drv_writeDstOffset(channel, dstOffset);
  mcuxClDma_Sfr_writeTransferAttributes(channel, MCUXCLDMA_DRV_SRC_ACCESS_SIZE(srcSize)
                                                | MCUXCLDMA_DRV_DST_ACCESS_SIZE(dstSize));
  mcuxClDma_Drv_writeLastSrcAddrAdjustment(channel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS); /* Do not adjust src address in TCD after transfer completion, default setting */
  mcuxClDma_Drv_writeLastDstAddrAdjustment(channel, MCUXCLDMA_DRV_FINAL_OFFSET_DIS); /* Do not adjust dst address in TCD after transfer completion, default setting */
  mcuxClDma_Sfr_writeTCDControlAndStatus(channel, 0u);
}
