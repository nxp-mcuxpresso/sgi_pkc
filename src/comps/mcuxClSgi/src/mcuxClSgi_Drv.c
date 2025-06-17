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

#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClPrng_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslAnalysis.h>

/** Waits until SGI operation finished */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_wait)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_wait(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_wait);
  while(MCUXCLSGI_SFR_STATUS_BUSY(mcuxClSgi_Sfr_readStatus())) {/*nothing*/}
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_wait);
}

/** Initializes SGI by setting CTRL to 0 and CTRL2 to the provided value. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_init)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_init(uint32_t mode)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_init);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());
  mcuxClSgi_Sfr_writeCtrl(0u);
  mcuxClSgi_Sfr_writeCtrl2(mode);
#ifdef SGI_HAS_AES_AUTO_MODE
  /* Known bug in SGI AUTO mode: if AUTO_MODE.CMD is not reset to 0 here, subsequent SGI operations will not work.
     Workaround: Reset AUTO_MODE to 0. To be removed in CLNS-7392 once fixed in HW. */
  mcuxClSgi_Drv_resetAutoMode();
#endif /* SGI_HAS_AES_AUTO_MODE */

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_init);
}

/** Closes SGI after usage, returns error state. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_close)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_close(mcuxClSession_Handle_t session)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_close);

#ifdef SGI_HAS_AES_AUTO_MODE
  /* Stop and disable AUTO mode - might still be running from CTR blocking mode */
  /* TODO CLNS-6458/CLNS-6459/CLNS-6455/CLNS-6460, Non-Blocking modes: clean-ups like this may only be done for blocking modes! */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopAndDisableAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopAndDisableAutoMode());
#endif /* SGI_HAS_AES_AUTO_MODE */

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_readAccessError));
  MCUX_CSSL_FP_FUNCTION_CALL(accessErrorStatus, mcuxClSgi_Drv_readAccessError(session));
  if(MCUXCLSGI_STATUS_OK != accessErrorStatus)
  {
    MCUXCLSESSION_ERROR(session, accessErrorStatus);
  }

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_readStatusError));
  MCUX_CSSL_FP_FUNCTION_CALL(errorStatus, mcuxClSgi_Drv_readStatusError(session));

  if(MCUXCLSGI_STATUS_OK != errorStatus)
  {
    MCUXCLSESSION_ERROR(session, MCUXCLSGI_STATUS_ERROR);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_close);
}

#ifdef SGI_HAS_AES_AUTO_MODE
/** Configures the SGI in AUTO mode for Cipher/MAC operations.
    autoModeConfig: Enable/Disable AUTO mode, set command (ECB/CBC/CTR/CMAC), counter_incr */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_configureAutoMode)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_configureAutoMode(uint32_t autoModeConfig)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_configureAutoMode);

  mcuxClSgi_Sfr_writeAutoMode(autoModeConfig);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_configureAutoMode);
}

/** Resets the SGI in AUTO mode to 0. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_resetAutoMode)
void mcuxClSgi_Drv_resetAutoMode(void)
{
  mcuxClSgi_Sfr_writeAutoMode(0u);
}

/** Stops a Cipher/MAC operation in AUTO mode, disables AUTO mode */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_stopAndDisableAutoMode)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_stopAndDisableAutoMode(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_stopAndDisableAutoMode);
  /* It is important not just overwrite the whole AUTO_MODE SFR, as CMD must not be modified while SGI is running.
     Wait for SGI does not make sense at this point because the busy flag will stay asserted until the
     final result block was read. */

  uint32_t autoMode = mcuxClSgi_Sfr_readAutoMode();
  autoMode &= ~MCUXCLSGI_SFR_AUTO_MODE_EN;

  /* Known limitation for CBCMAC mode: Reset ENABLE and set STOP should be 2 seperate SFR accesses. */
  mcuxClSgi_Sfr_writeAutoMode(autoMode);
  mcuxClSgi_Sfr_writeAutoMode(autoMode | MCUXCLSGI_SFR_AUTO_MODE_STOP);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_stopAndDisableAutoMode);
}

/** Enables input and output FIFO DMA handshakes for AUTO mode */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableDmaHandshakes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_enableDmaHandshakes(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_enableDmaHandshakes);
  mcuxClSgi_Sfr_writeAutoDmaCtrl(MCUXCLSGI_SFR_AUTO_MODE_DMA_IFE_EN | MCUXCLSGI_SFR_AUTO_MODE_DMA_OFE_EN);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_enableDmaHandshakes);
}

/** Disables input and output FIFO DMA handshake for AUTO mode */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_disableDmaHandshakes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_disableDmaHandshakes(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_disableDmaHandshakes);
  mcuxClSgi_Sfr_writeAutoDmaCtrl(0u);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_disableDmaHandshakes);
}

/** Enables input FIFO DMA handshake for AUTO mode */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableInputDmaHandshake)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_enableInputDmaHandshake(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_enableInputDmaHandshake);
  const uint32_t autoDmaCtrl = mcuxClSgi_Sfr_readAutoDmaCtrl();
  mcuxClSgi_Sfr_writeAutoDmaCtrl(autoDmaCtrl | MCUXCLSGI_SFR_AUTO_MODE_DMA_IFE_EN);
MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_enableInputDmaHandshake);
}

/** Disables input FIFO DMA handshake for AUTO mode */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_disableInputDmaHandshake)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_disableInputDmaHandshake(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_disableInputDmaHandshake);
  const uint32_t autoDmaCtrl = mcuxClSgi_Sfr_readAutoDmaCtrl();
  mcuxClSgi_Sfr_writeAutoDmaCtrl(autoDmaCtrl & (~MCUXCLSGI_SFR_AUTO_MODE_DMA_IFE_EN));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_disableInputDmaHandshake);
}

#endif /* SGI_HAS_AES_AUTO_MODE */

/** Starts an SGI operation
  Operation: mode(Aes,Des...), Enc/Dec, KeySize, inXor,outXor, KeySel, DatinSel */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_start)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_start(uint32_t operation)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_start);
  mcuxClSgi_Sfr_writeCtrl(operation | MCUXCLSGI_SFR_CTRL_START);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_start);
}

/** Stops SHA2 operation */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_stopSha2)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_stopSha2(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_stopSha2);
  /* Read SHA2_CTRL SFR */
  const uint32_t ctrlsha2 = mcuxClSgi_Sfr_readSha2Ctrl();

  /* Stop SHA-2 operation */
  mcuxClSgi_Sfr_writeSha2Ctrl(ctrlsha2 | MCUXCLSGI_SFR_CTRL_SHA2_SHA2_STOP);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_stopSha2);
}

/** Gets control value (CTRL) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_getCtrl)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_getCtrl(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_getCtrl);
  uint32_t ctrl = mcuxClSgi_Sfr_readCtrl();
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_getCtrl, ctrl);
}

/** Gets control value (CTRL2) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_getCtrl2)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_getCtrl2()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_getCtrl2);
  uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_getCtrl2, ctrl2);
}

/** Sets control value (CTRL) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_setCtrl)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_setCtrl(uint32_t control)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_setCtrl);
  mcuxClSgi_Sfr_writeCtrl(control);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_setCtrl);
}

/** Sets control value (CTRL2) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_setCtrl2)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_setCtrl2(uint32_t control)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_setCtrl2);
  mcuxClSgi_Sfr_writeCtrl2(control);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_setCtrl2);
}

/** Configures SHA-2 operation (SHA2_CTRL) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_configureSha2)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_configureSha2(uint32_t control)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_configureSha2);
  mcuxClSgi_Sfr_writeSha2Ctrl(control);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_configureSha2);
}

/** Configure SHA-2 operation; disable IV AUTO-INIT */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_disableIvAutoInit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_disableIvAutoInit(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_disableIvAutoInit);
    /* Read SHA2_CTRL SFR */
  const uint32_t ctrlsha2 = mcuxClSgi_Sfr_readSha2Ctrl();

  mcuxClSgi_Sfr_writeSha2Ctrl(ctrlsha2 | (MCUXCLSGI_SFR_CTRL_SHA2_NO_AUTO_INIT));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_disableIvAutoInit);
}

/** Flush all/key/datain */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableFlush)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_enableFlush(uint32_t option)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_enableFlush);
  /* Backup CTRL2 SFR */
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  /* Enable flush write mode */
  mcuxClSgi_Sfr_writeCtrl2(ctrl2 | option);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_enableFlush);
}

/** Enables masking - next load/store of data/key will use masking
 * Returns previous control value */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableMasking)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_enableMasking(uint32_t type, uint32_t mask)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_enableMasking);

  /* Backup CTRL2 SFR */
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  /* Enable masking */
  mcuxClSgi_Sfr_writeCtrl2((ctrl2 & (~(MCUXCLSGI_SFR_CTRL2_SMASKSW | MCUXCLSGI_SFR_CTRL2_SMASKSTEP))) | type);

  mcuxClSgi_Sfr_writeSfrSeed(mask);

  /* Return the backup */
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_enableMasking, ctrl2);
}

/** Set dummy cycles */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_setDummyCycles)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_setDummyCycles(uint32_t dummyCycles)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_setDummyCycles);
  dummyCycles = MCUXCLSGI_SFR_DUMMY_CTRL_ADCTRL(dummyCycles);   /*set the dummy cycles for the AES*/

  mcuxClSgi_Sfr_setDummyCtrl(dummyCycles);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_setDummyCycles);
}

/** Read dummy cycles */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_readDummyCycles)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_readDummyCycles(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_readDummyCycles);
  uint32_t dummyCtrl = mcuxClSgi_Sfr_readDummyCtrl();

  uint32_t dummyCycles = ((dummyCtrl & MCUXCLSGI_SFR_DUMMY_CTRL_ADCTRL_MASK) >> MCUXCLSGI_SFR_DUMMY_CTRL_ADCTRL_POS);

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_readDummyCycles, dummyCycles);
}

/** Enable and init counter for SHA-2 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableHashCounter)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_enableHashCounter(uint32_t cntVal)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_enableHashCounter);

  /* Enable counter */
  const uint32_t ctrl = mcuxClSgi_Sfr_readSha2Ctrl();
  mcuxClSgi_Sfr_writeSha2Ctrl(ctrl | MCUXCLSGI_SFR_CTRL_SHA2_COUNT_EN);

  /* Initialize counter */
  mcuxClSgi_Sfr_writeCount(cntVal);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_enableHashCounter);
}

/** Compare counter value */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_checkHashCounter)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_checkHashCounter(mcuxClSession_Handle_t session, uint32_t expectedCounterValue)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_checkHashCounter);

  if(expectedCounterValue != mcuxClSgi_Sfr_readCount())
  {
    MCUXCLSESSION_FAULT(session, MCUXCLSGI_STATUS_FAULT);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_checkHashCounter);
}

/* Get the SGI Calculation counter value*/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_getCount)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_getCount(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_getCount);
  uint32_t count = mcuxClSgi_Sfr_readCount();
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_getCount, count);
}

/** Fetch key into a key register  */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_loadKeyWord)
void mcuxClSgi_Drv_loadKeyWord(uint32_t registerIndex, uint32_t key)
{
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_VOID(registerIndex, 0U, 7U);
  mcuxClSgi_Sfr_writeWord(MCUXCLSGI_SFR_KEY_INDEX_TO_OFFSET(registerIndex), key);
}

/* Increments by 1 (with carry) value in datin */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_incrementData)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_incrementData(uint32_t offset, uint32_t length)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_incrementData);
  uint32_t config2 = mcuxClSgi_Sfr_readCtrl2();
  mcuxClSgi_Sfr_writeCtrl2(config2 | MCUXCLSGI_SFR_CTRL2_INCR);
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(length, 0u, 16u);
  length >>= MCUXCLSGI_SFR_BYTES_TO_32BIT_WORD_SHIFT;    /* calculate length in a word*/

  /* Increment from last to first */
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(offset, 0u, MCUXCLSGI_DRV_DATIN2_OFFSET);
  while(0u != length)
  {
    length --;
    /* Protect the number of loop executions */
    MCUX_CSSL_DI_EXPUNGE(incLength, sizeof(uint32_t));
    /* writing something to DATIN - this will trigger incrementation */
    mcuxClSgi_Sfr_writeWord(offset + (4u*length), 1u);
    mcuxClSgi_Sfr_writeCtrl2(config2 | MCUXCLSGI_SFR_CTRL2_INCR | MCUXCLSGI_SFR_CTRL2_INCR_CIN);
  }

  //Restore config
  mcuxClSgi_Sfr_writeCtrl2(config2);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_incrementData);
}

/** Set byte order
 * Returns previous control value*/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_setByteOrder)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_setByteOrder(uint32_t mode)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_setByteOrder);
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  mcuxClSgi_Sfr_writeCtrl2((ctrl2 & (~MCUXCLSGI_SFR_CTRL2_BYTES_ORDER_MASK)) | mode );

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_setByteOrder, ctrl2);
}

/** Enables xor on write
 * Returns previous control value*/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableXorWrite)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_enableXorWrite(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_enableXorWrite);
  /* Backup CTRL2 SFR */
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  /* Enable flush write mode */
  mcuxClSgi_Sfr_writeCtrl2(ctrl2 | MCUXCLSGI_SFR_CTRL2_XORWR);

  /* Return the backup */
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_enableXorWrite, ctrl2);
}

/** Disable xor on write */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_disableXorWrite)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_disableXorWrite(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_disableXorWrite);
  /* Backup CTRL2 SFR */
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  /* Disable xor on write mode */
  mcuxClSgi_Sfr_writeCtrl2(ctrl2 & (~MCUXCLSGI_SFR_CTRL2_XORWR));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_disableXorWrite);
}

/** Fetch data into a data register  */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_loadWord)
void mcuxClSgi_Drv_loadWord(uint32_t offset, uint32_t data)
{
  mcuxClSgi_Sfr_writeWord(offset, data);
}

/** Write SHA-2 input data to FIFO */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_loadFifo)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_loadFifo(uint32_t data)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_loadFifo);
  mcuxClSgi_Sfr_writeFifoWord(data);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_loadFifo);
}

/** Enables storing output in key register
  * Returns previous control value*/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableOutputToKey)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_enableOutputToKey(uint32_t keyIndex)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_enableOutputToKey);
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  /* Enables storing output in key register */
  mcuxClSgi_Sfr_writeCtrl2((ctrl2 & (~MCUXCLSGI_SFR_CTRL2_KEYRES_MASK)) | MCUXCLSGI_SFR_CTRL2_KEYRES(keyIndex) | MCUXCLSGI_SFR_CTRL2_RKEY);

  /* Return the backup */
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_enableOutputToKey, ctrl2);
}

/** Disable output to key */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_disableOutputToKey)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_disableOutputToKey(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_disableOutputToKey);
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  mcuxClSgi_Sfr_writeCtrl2(ctrl2 & (~MCUXCLSGI_SFR_CTRL2_RKEY));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_disableOutputToKey);
}

/** Trigger writing result to DATOUT */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_triggerOutput)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_triggerOutput(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_triggerOutput);
  const uint32_t ctrl = mcuxClSgi_Sfr_readCtrl();
  mcuxClSgi_Sfr_writeCtrl(ctrl | MCUXCLSGI_SFR_CTRL_TRIGGER_UP | MCUXCLSGI_SFR_CTRL_START);
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_triggerOutput);
}

/** Get result from output register */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_storeWord)
uint32_t mcuxClSgi_Drv_storeWord(uint32_t offset)
{
  return mcuxClSgi_Sfr_readWord(offset);
}

/** Get current value of Sfr Seed */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_getSfrSeed)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_getSfrSeed(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_getSfrSeed);
  uint32_t seed = mcuxClSgi_Sfr_readSfrSeed();
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_getSfrSeed, seed);
}

/** Check error status  */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_readStatusError)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSgi_Status_t) mcuxClSgi_Drv_readStatusError(mcuxClSession_Handle_t session)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_readStatusError);

  if(MCUXCLSGI_SFR_STATUS_ERROR(mcuxClSgi_Sfr_readStatus()))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_readStatusError, MCUXCLSGI_STATUS_ERROR);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_readStatusError, MCUXCLSGI_STATUS_OK);
}

/** Check for access errors */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_readAccessError)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSgi_Status_t) mcuxClSgi_Drv_readAccessError(mcuxClSession_Handle_t session)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_readAccessError);

#ifdef SGI_HAS_ACCESS_ERR
  if (MCUXCLSGI_SFR_ACCESS_ERROR(mcuxClSgi_Sfr_readAccessError()))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_readAccessError, MCUXCLSGI_STATUS_ERROR);
  }
#endif /* SGI_HAS_ACCESS_ERR */
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_readAccessError, MCUXCLSGI_STATUS_OK);
}

/** Enables flush-on-write. Returns previous control value */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableFlushWr)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClSgi_Drv_enableFlushWr(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_enableFlushWr);
  /* Backup CTRL2 SFR */
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  /* Enable flush write mode */
  mcuxClSgi_Sfr_writeCtrl2(ctrl2 | MCUXCLSGI_SFR_CTRL2_FLUSHWR);

  /* Return the backup */
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSgi_Drv_enableFlushWr, ctrl2);
}

/** Disables flush on write */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_disableFlushWr)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_disableFlushWr(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_disableFlushWr);
  /* Backup CTRL2 SFR */
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  /* Enable flush write mode */
  mcuxClSgi_Sfr_writeCtrl2(ctrl2 & (~MCUXCLSGI_SFR_CTRL2_FLUSHWR));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_disableFlushWr);
}

/** Flush consecutive register banks with random data */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_flushRegisterBanks)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Drv_flushRegisterBanks(
  uint32_t offset,
  uint32_t numberOfWords)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Drv_flushRegisterBanks);

  uint32_t *const sgiSfrAddress = mcuxClSgi_Sfr_getAddr(offset);

#ifdef SGI_HAS_FLUSHWR /* SGI has the flush on write functionality available */

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableFlushWr));
  MCUX_CSSL_FP_FUNCTION_CALL(ctrl2Backup, mcuxClSgi_Drv_enableFlushWr());

  for(uint32_t i = 0U; i < numberOfWords; i++)
  {
    /* Writing any value to an SFR while flush-on-write is enabled causes random data to be written instead */
    sgiSfrAddress[i] = 0xffUL;
  }

  mcuxClSgi_Sfr_writeCtrl2(ctrl2Backup);

#else /* Flush on write not available, write manually random words to the register banks */

  MCUXCLPRNG_INIT();

  for(uint32_t i = 0U; i < numberOfWords; i++)
  {
    /* Writing random value to SFR */
    MCUXCLPRNG_GET_WORD(rng);
    sgiSfrAddress[i] = rng;
  }

  MCUXCLPRNG_RESTORE();

#endif /* SGI_HAS_FLUSHWR */

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Drv_flushRegisterBanks);
}

#if 0  /* Disable below unused functions, but keep those disabled functions for possible future use*/
/** Configures SHA-2 operation (SHA2_CTRL) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_enableHashReload)
void mcuxClSgi_Drv_enableHashReload(void)
{
    /* Read SHA2_CTRL SFR */
    const uint32_t ctrlsha2 = mcuxClSgi_Sfr_readSha2Ctrl();

    mcuxClSgi_Sfr_writeSha2Ctrl(ctrlsha2 & MCUXCLSGI_SFR_CTRL_SHA2_HASH_RELOAD);
}

/** Configures SHA-2 operation (SHA2_CTRL) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_disableHashReload)
void mcuxClSgi_Drv_disableHashReload(void)
{
    /* Read SHA2_CTRL SFR */
    const uint32_t ctrlsha2 = mcuxClSgi_Sfr_readSha2Ctrl();

    mcuxClSgi_Sfr_writeSha2Ctrl(ctrlsha2 & (~MCUXCLSGI_SFR_CTRL_SHA2_HASH_RELOAD));
}

/** Returns current value of mask - needs to be passed to next enableMasking() call*/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_getMaskValue)
uint32_t mcuxClSgi_Drv_getMaskValue(void)
{
  /* Backup CTRL2 SFR */
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  /* Enable masking to read seed */
  mcuxClSgi_Sfr_writeCtrl2(ctrl2 | MCUXCLSGI_SFR_CTRL2_SMASKEN);

  uint32_t mask = mcuxClSgi_Sfr_readSfrSeed();

  mcuxClSgi_Sfr_writeCtrl2(ctrl2);

  return mask;
}

/** Disable masking data/key */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_disableMasking)
void mcuxClSgi_Drv_disableMasking(void)
{
  const uint32_t ctrl2 = mcuxClSgi_Sfr_readCtrl2();

  mcuxClSgi_Sfr_writeCtrl2((ctrl2 & (~MCUXCLSGI_SFR_CTRL2_SMASKEN)) | MCUXCLSGI_SFR_CTRL2_SMASKSW);
}

/** Enable noise */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_setNoise)
uint32_t mcuxClSgi_Drv_setNoise(uint32_t noise)
{
  const uint32_t ctrl = mcuxClSgi_Sfr_readCtrl();

  /* Enables storing output in key register */
  mcuxClSgi_Sfr_writeCtrl((ctrl &  ~(MCUXCLSGI_DRV_AES_NOISE_EN)) | noise);

  /* Return the backup */
  return ctrl;
}

/** Set data out  */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Drv_dataOut_res)
uint32_t mcuxClSgi_Drv_dataOut_res(uint32_t mode)
{
  const uint32_t ctrl = mcuxClSgi_Sfr_readCtrl();

   /* Selects whether to store the SGI result to DATOUT, or whether to XOR it with data from DATIN register banks */
  mcuxClSgi_Sfr_writeCtrl((ctrl &  ~(MCUXCLSGI_SFR_CTRL_OUTSEL_MASK)) | mode);

  /* Return the backup */
  return ctrl;
}
#endif
