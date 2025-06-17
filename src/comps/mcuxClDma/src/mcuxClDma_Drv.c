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

#include <mcuxClToolchain.h>
#include <internal/mcuxClDma_Drv.h>
#include <internal/mcuxClDma_Sfr.h>
#include <mcuxClDma_Types.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>


/***************************************************/
/*     Static (internal) driver functions          */
/***************************************************/

/**
 * @brief Checks the given channel for errors and returns a descriptive status code.
 *
 * This function shall not be used outside of the mcuxClDma component.
 * For this purpose, @ref mcuxClDma_Drv_checkForChannelErrors is available.
 *
 * @param  channel    The DMA channel
 *
 * @return Status error code of the channel
 * @retval #MCUXCLDMA_STATUS_OK                     if channel execution was OK
 * @retval #MCUXCLDMA_STATUS_SOURCE_BUS_ERROR       if the provided source address is not accessible with the DMA, or other source bus error
 * @retval #MCUXCLDMA_STATUS_DESTINATION_BUS_ERROR  if the provided destination address is not accessible with the DMA, or other destination bus error
 * @retval #MCUXCLDMA_STATUS_CONFIGURATION_ERROR    if an error in the DMA configuration was detected
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_readAndTranslateChannelErrors)
static inline mcuxClDma_Status_t mcuxClDma_Drv_readAndTranslateChannelErrors(
  mcuxClSession_Channel_t channel)
{
  uint32_t errorStatus = mcuxClDma_Sfr_readChannelErrorStatus(channel);

  if(1UL == MCUXCLDMA_SFR_CH_ES_ERR(errorStatus))
  {
    if(1UL == MCUXCLDMA_SFR_CH_ES_SBE(errorStatus))
    {
      return MCUXCLDMA_STATUS_SOURCE_BUS_ERROR;
    }
    if(1UL == MCUXCLDMA_SFR_CH_ES_DBE(errorStatus))
    {
      return MCUXCLDMA_STATUS_DESTINATION_BUS_ERROR;
    }
    return MCUXCLDMA_STATUS_CONFIGURATION_ERROR;
  }

  return MCUXCLDMA_STATUS_OK;
}


/***************************************************/
/*               Driver functions                  */
/***************************************************/

/** Checks the given channel for errors and throws a descriptive error code via early-exit. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_checkForChannelErrors)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_Drv_checkForChannelErrors(
  mcuxClSession_Handle_t session,
  mcuxClSession_Channel_t channel)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClDma_Drv_checkForChannelErrors);

  uint32_t errorStatus = mcuxClDma_Sfr_readChannelErrorStatus(channel);

  if(1UL == MCUXCLDMA_SFR_CH_ES_ERR(errorStatus))
  {
    if(1UL == MCUXCLDMA_SFR_CH_ES_SBE(errorStatus))
    {
      MCUXCLSESSION_ERROR(session, MCUXCLDMA_STATUS_SOURCE_BUS_ERROR);
    }
    if(1UL == MCUXCLDMA_SFR_CH_ES_DBE(errorStatus))
    {
      MCUXCLSESSION_ERROR(session, MCUXCLDMA_STATUS_DESTINATION_BUS_ERROR);
    }
    MCUXCLSESSION_ERROR(session, MCUXCLDMA_STATUS_CONFIGURATION_ERROR);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClDma_Drv_checkForChannelErrors);
}

/** Clear the error status of the given DMA channel. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_clearErrorFlags)
void mcuxClDma_Drv_clearErrorFlags(mcuxClSession_Channel_t channel)
{
  mcuxClDma_Sfr_writeChannelErrorStatus(channel, MCUXCLDMA_SFR_CH_ES_CLEAR);
}

/** Enable hardware requests for a specific DMA channel. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_enableHardwareRequests)
void mcuxClDma_Drv_enableHardwareRequests(mcuxClSession_Channel_t channel)
{
  mcuxClDma_Sfr_enableHardwareRequest(channel);
}

/** Enable error interrupts for a specific DMA channel. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_enableErrorInterrupts)
void mcuxClDma_Drv_enableErrorInterrupts(mcuxClSession_Channel_t channel)
{
  mcuxClDma_Sfr_writeChannelErrorStatus(channel, MCUXCLDMA_SFR_CH_ES_CLEAR);
  MCUXCLDMA_SFR_CH_CSR_ENABLE_FIELD(channel, EEI);
}

/** Disable error interrupts for a specific DMA channel. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_disableErrorInterrupts)
void mcuxClDma_Drv_disableErrorInterrupts(mcuxClSession_Channel_t channel)
{
  MCUXCLDMA_SFR_CH_CSR_DISABLE_FIELD(channel, EEI);
}

/** Enable major loop interrupts for a specific DMA channel. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_enableChannelDoneInterrupts)
void mcuxClDma_Drv_enableChannelDoneInterrupts(mcuxClSession_Channel_t channel)
{
  MCUXCLDMA_SFR_TCD_CSR_ENABLE_FIELD(channel, INTMAJOR);
}

/** Disable major loop interrupts for a specific DMA channel. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_disableChannelDoneInterrupts)
void mcuxClDma_Drv_disableChannelDoneInterrupts(mcuxClSession_Channel_t channel)
{
  MCUXCLDMA_SFR_TCD_CSR_DISABLE_FIELD(channel, INTMAJOR);
}

/** Clear the interrupt request status of the given channel. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_clearInterruptRequestStatus)
void mcuxClDma_Drv_clearInterruptRequestStatus(mcuxClSession_Channel_t channel)
{
  mcuxClDma_Sfr_writeChannelInterruptStatus(channel, 1u); // W1C
}

#if 0
/** Write the source transfer size. Assumes already shifted value. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeSrcAccessSize)
void mcuxClDma_Drv_writeSrcAccessSize(mcuxClSession_Channel_t channel, uint16_t accessSize)
{
  MCUXCLDMA_SFR_TCD_ATTR_WRITE_FIELD(channel, SSIZE, accessSize);
}
#endif

#if 0
/** Write the destination transfer size. Assumes already shifted value. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeDstAccessSize)
void mcuxClDma_Drv_writeDstAccessSize(mcuxClSession_Channel_t channel, uint16_t accessSize)
{
  MCUXCLDMA_SFR_TCD_ATTR_WRITE_FIELD(channel, DSIZE, accessSize);
}
#endif

/** Write the source offset. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeSrcOffset)
void mcuxClDma_Drv_writeSrcOffset(mcuxClSession_Channel_t channel, uint16_t srcOffset)
{
  mcuxClDma_Sfr_writeSrcOffset(channel, srcOffset);
}

/** Write the destination offset. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeDstOffset)
void mcuxClDma_Drv_writeDstOffset(mcuxClSession_Channel_t channel, uint16_t dstOffset)
{
  mcuxClDma_Sfr_writeDstOffset(channel, dstOffset);
}

/** Write the source address of a DMA channel TCD. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeSrcAddress)
void mcuxClDma_Drv_writeSrcAddress(mcuxClSession_Channel_t channel, const uint8_t *pSrc)
{
  mcuxClDma_Sfr_writeSrcAddress(channel, pSrc);
}

/** Write the destination address of a DMA channel TCD. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeDstAddress)
void mcuxClDma_Drv_writeDstAddress(mcuxClSession_Channel_t channel, uint8_t *pDst)
{
  mcuxClDma_Sfr_writeDstAddress(channel, pDst);
}

#if 0
/** Read the destination address of a DMA channel TCD. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_readDstAddress)
uint8_t* mcuxClDma_Drv_readDstAddress(mcuxClSession_Channel_t channel)
{
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_INTEGER_TO_POINTER("Convert configured DMA channel destination address back to a pointer.")
  uint8_t* pDst = (uint8_t*)mcuxClDma_Sfr_readDstAddress(channel);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_INTEGER_TO_POINTER()
  return pDst;
}
#endif

#if 0
/** Read the source address of a DMA channel TCD. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_readSrcAddress)
uint8_t* mcuxClDma_Drv_readSrcAddress(mcuxClSession_Channel_t channel)
{
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_INTEGER_TO_POINTER("Convert configured DMA channel source address back to a pointer.")
  uint8_t* pSrc = (uint8_t*)mcuxClDma_Sfr_readSrcAddress(channel);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_INTEGER_TO_POINTER()
  return pSrc;
}
#endif

/** Start a channel by asserting the START bit. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_startChannel)
void mcuxClDma_Drv_startChannel(mcuxClSession_Channel_t channel)
{
  MCUXCLDMA_SFR_TCD_CSR_ENABLE_FIELD(channel, START);
}

/** Wait for channel DONE flag, check for errors */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_waitForChannelDone)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_Drv_waitForChannelDone(
  mcuxClSession_Handle_t session,
  mcuxClSession_Channel_t channel)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClDma_Drv_waitForChannelDone);

  uint32_t chCsr = 0u;
  mcuxClDma_Status_t chErrStatus = 0u;
  do
  {
    chErrStatus = mcuxClDma_Drv_readAndTranslateChannelErrors(channel);
    if(MCUXCLDMA_STATUS_OK != chErrStatus)
    {
      /* Clear error status */
      mcuxClDma_Drv_clearErrorFlags(channel);
      /* error in DMA channel - return error code */
      MCUXCLSESSION_ERROR(session, chErrStatus);
    }
    chCsr = mcuxClDma_Sfr_readChannelControlAndStatus(channel);
  } while(1u != MCUXCLDMA_SFR_CH_CSR_DONE(chCsr));

  /* Clear the DONE flag - clear on write */
  MCUXCLDMA_SFR_CH_CSR_ENABLE_FIELD(channel, DONE);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClDma_Drv_waitForChannelDone);
}


/** Wait for channel DONE flag of both channels, check for errors */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_waitForHandshakeChannelsDone)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_Drv_waitForHandshakeChannelsDone(
  mcuxClSession_Handle_t session)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClDma_Drv_waitForHandshakeChannelsDone);

  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  mcuxClDma_Status_t chInErrStatus = 0u;
  mcuxClDma_Status_t chOutErrStatus = 0u;
  uint32_t chInCsr = 0u;
  uint32_t chOutCsr = 0u;

  do
  {
    chOutErrStatus = mcuxClDma_Drv_readAndTranslateChannelErrors(outputChannel);
    if(MCUXCLDMA_STATUS_OK != chOutErrStatus)
    {
      /* Clear error status */
      mcuxClDma_Drv_clearErrorFlags(outputChannel);
      mcuxClDma_Drv_clearErrorFlags(inputChannel);
      /* error in DMA output channel - return error code */
      MCUXCLSESSION_ERROR(session, chOutErrStatus);
    }
    chInErrStatus = mcuxClDma_Drv_readAndTranslateChannelErrors(inputChannel);
    if(MCUXCLDMA_STATUS_OK != chInErrStatus)
    {
      /* Clear error status */
      mcuxClDma_Drv_clearErrorFlags(outputChannel);
      mcuxClDma_Drv_clearErrorFlags(inputChannel);
      /* error in DMA input channel - return error code */
      MCUXCLSESSION_ERROR(session, chInErrStatus);
    }

    chOutCsr = mcuxClDma_Sfr_readChannelControlAndStatus(outputChannel);
  } while(1u != MCUXCLDMA_SFR_CH_CSR_DONE(chOutCsr));

  do
  {
    chInErrStatus = mcuxClDma_Drv_readAndTranslateChannelErrors(inputChannel);
    if(MCUXCLDMA_STATUS_OK != chInErrStatus)
    {
      /* Clear error status */
      mcuxClDma_Drv_clearErrorFlags(outputChannel);
      mcuxClDma_Drv_clearErrorFlags(inputChannel);
      /* error in DMA input channel - return error code */
      MCUXCLSESSION_ERROR(session, chInErrStatus);
    }
    chInCsr = mcuxClDma_Sfr_readChannelControlAndStatus(inputChannel);
  } while(1u != MCUXCLDMA_SFR_CH_CSR_DONE(chInCsr));

  /* Clear the DONE flags - clear on write */
  MCUXCLDMA_SFR_CH_CSR_ENABLE_FIELD(outputChannel, DONE);
  MCUXCLDMA_SFR_CH_CSR_ENABLE_FIELD(inputChannel, DONE);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClDma_Drv_waitForHandshakeChannelsDone);
}

/** Link the SGI I/O Handshake signals to the DMA channels within the SCM peripheral */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_linkWithSgiHandshakes)
void mcuxClDma_Drv_linkWithSgiHandshakes(
  mcuxClSession_Handle_t session)
{
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outputChannel = mcuxClSession_getDmaOutputChannel(session);

  /* Enable the hardware service requests for the channels */
  mcuxClDma_Sfr_enableHardwareRequest(inputChannel);
  mcuxClDma_Sfr_enableHardwareRequest(outputChannel);

  /* Link the SGI Handshake signals to the DMA channels by selection the hardware request source */
  mcuxClDma_Sfr_setSrcSelect(inputChannel, MCUXCLDMA_DRV_HWREQ_SRC_SGI_IN);
  mcuxClDma_Sfr_setSrcSelect(outputChannel, MCUXCLDMA_DRV_HWREQ_SRC_SGI_OUT);
}

/** Link the SGI input Handshake signals to the DMA channel within the SCM peripheral */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_linkWithSgiInputHandshakes)
void mcuxClDma_Drv_linkWithSgiInputHandshakes(
  mcuxClSession_Handle_t session)
{
  mcuxClSession_Channel_t inputChannel = mcuxClSession_getDmaInputChannel(session);

  /* Enable the DMA channel service requests */
  mcuxClDma_Sfr_enableHardwareRequest(inputChannel);

  /* Link the SGI Handshake signals to the DMA channel by setting the src in the channel mux */
  mcuxClDma_Sfr_setSrcSelect(inputChannel, MCUXCLDMA_DRV_HWREQ_SRC_SGI_IN);
}


/** Write the value which will be added to the source address on channel completion. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeLastSrcAddrAdjustment)
void mcuxClDma_Drv_writeLastSrcAddrAdjustment(
  mcuxClSession_Channel_t channel,
  uint32_t offset)
{
  /* Write the last source address offset */
  mcuxClDma_Sfr_writeSrcLast_writeStoreDstAddr(channel, offset);

  /* Disable ESDA in the TCD CSR register */
  MCUXCLDMA_SFR_TCD_CSR_DISABLE_FIELD(channel, ESDA);
}

#if 0
/** Write the "store final destination address" value to the DMA channel TCD, and enable TCDn_CSR.ESDA. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeStoreFinalDstAddr)
void mcuxClDma_Drv_writeStoreFinalDstAddr(
  mcuxClSession_Channel_t channel,
  uint32_t address)
{
  /* Write the last source address offset */
  mcuxClDma_Sfr_writeSrcLast_writeStoreDstAddr(channel, address);

  /* Enable ESDA in the TCD CSR register */
  MCUXCLDMA_SFR_TCD_CSR_ENABLE_FIELD(channel, ESDA);
}
#endif

/** Write the major loop counts to the DMA channel TCD, disable channel-to-channel linking */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeMajorLoopCounts)
void mcuxClDma_Drv_writeMajorLoopCounts(
  mcuxClSession_Channel_t channel,
  uint16_t count)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_SFR_ACCESS()
  /* Write BITER and CITER, must be equal at the start of a transfer */
  MCUXCLDMA_SFR_TCD_BITER_ELINKNO_WRITE_FIELD(channel, BITER, count);
  MCUXCLDMA_SFR_TCD_CITER_ELINKNO_WRITE_FIELD(channel, CITER, count);

  /* Disable ELINK */
  MCUXCLDMA_TCD_SFR_BITFIELD_CLEAR(channel, BITER_ELINKNO, ELINK);
  MCUXCLDMA_TCD_SFR_BITFIELD_CLEAR(channel, CITER_ELINKNO, ELINK);
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SFR_ACCESS()
}

/** Read the major beginning loop count from the DMA channel TCD, disable channel-to-channel linking */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_readMajorBeginningLoopCount)
uint16_t mcuxClDma_Drv_readMajorBeginningLoopCount(
  mcuxClSession_Channel_t channel)
{
  /* Read BITER count */
  MCUX_CSSL_ANALYSIS_START_PATTERN_SFR_ACCESS()
  return MCUXCLDMA_SFR_TCD_BITER_ELINKNO_READ_FIELD(channel, BITER);
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SFR_ACCESS()
}

#if 0
/** Write the major loop counts to the DMA channel TCD, enable and configure channel-to-channel linking. */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeMajorLoopCounts_withChannelLinking)
void mcuxClDma_Drv_writeMajorLoopCounts_withChannelLinking(
  mcuxClSession_Channel_t channel,
  uint16_t count,
  uint16_t linkingConfig)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  /* Write BITER and CITER, must be equal at the start of a transfer */
  mcuxClDma_Sfr_writeBeginningMajorLoopCountElink(channel, MCUXCLDMA_SFR_TCD_BITER_ELINKYES_BITER(count) | MCUXCLDMA_SFR_TCD_BITER_ELINKYES_ELINK_EN | linkingConfig);
  mcuxClDma_Sfr_writeCurrentMajorLoopCountElink(channel, MCUXCLDMA_SFR_TCD_CITER_ELINKYES_CITER(count) | MCUXCLDMA_SFR_TCD_CITER_ELINKYES_ELINK_EN | linkingConfig);
}
#endif

/** Write the transfer size to the DMA channel TCD, disable minor loop offsets */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeTransferSize)
void mcuxClDma_Drv_writeTransferSize(
  mcuxClSession_Channel_t channel,
  uint32_t size)
{
  /* clear SMLOE, DMLOE bits, and write the size */
  MCUX_CSSL_ANALYSIS_START_PATTERN_SFR_ACCESS()
  MCUXCLDMA_TCD_SFR_WRITE(channel, NBYTES_MLOFFNO, MCUXCLDMA_SFR_TCD_NBYTES_MLOFFNO_NBYTES(size));
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SFR_ACCESS()
}

#if 0
/** Write the transfer size to the DMA channel TCD, enable and configure minor loop offsets */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeTransferSizeWithMinorLoopOffsets)
void mcuxClDma_Drv_writeTransferSizeWithMinorLoopOffsets(
  mcuxClSession_Channel_t channel,
  uint32_t size,
  uint32_t minorLoopOffsetConfig)
{
  mcuxClDma_Sfr_writeTransferSizeMinorLoopOffset(channel, MCUXCLDMA_SFR_TCD_NBYTES_MLOFFYES_NBYTES(size) | minorLoopOffsetConfig);
}
#endif

/** Write the last destination address adjustment to the DMA channel TCD, and disable TCDn_CSR.ESG. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeLastDstAddrAdjustment)
void mcuxClDma_Drv_writeLastDstAddrAdjustment(
  mcuxClSession_Channel_t channel,
  uint32_t offset)
{
  /* Write the last source address offset */
  mcuxClDma_Sfr_writeDstLast_writeScatterGatherAddr(channel, offset);

  /* Disable ESDA in the TCD CSR register */
  MCUXCLDMA_SFR_TCD_CSR_DISABLE_FIELD(channel, ESG);
}

#if 0
/** Write the scatter-gather address to the DMA channel TCD, and enable TCDn_CSR.ESG. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_writeScatterGatherAddr)
void mcuxClDma_Drv_writeScatterGatherAddr(
  mcuxClSession_Channel_t channel,
  uint32_t address)
{
  /* Write the last source address offset */
  mcuxClDma_Sfr_writeDstLast_writeScatterGatherAddr(channel, address);

  /* Enable ESDA in the TCD CSR register */
  MCUXCLDMA_SFR_TCD_CSR_ENABLE_FIELD(channel, ESG);
}
#endif

/** Read the channelID in which an error occurred from the MP Error Status register. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_Drv_getChannelFromErrorStatus)
mcuxClSession_Channel_t mcuxClDma_Drv_getChannelFromErrorStatus(void)
{
  uint32_t errorStatus = mcuxClDma_Sfr_readErrorStatus();

  if( 0u == MCUXCLDMA_SFR_MP_ES_VLD(errorStatus))
  {
    return MCUXCLSESSION_DMACHANNEL_INVALID;
  }
  else
  {
    return (mcuxClSession_Channel_t) MCUXCLDMA_SFR_MP_ES_ERRCHN(errorStatus);
  }
}
