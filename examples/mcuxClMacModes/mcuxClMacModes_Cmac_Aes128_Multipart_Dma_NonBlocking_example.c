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
 * @example mcuxClMacModes_Cmac_Aes128_Multipart_Dma_NonBlocking_example.c
 * @brief mcuxClMacModes example application
 */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClAes.h> // Interface to AES-related definitions and types
#include <mcuxClMac.h> // Interface to the entire mcuxClMac component
#include <mcuxClMacModes.h> // Interface to the entire mcuxClMacModes component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClBuffer.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_OS.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

#include <platform_specific_headers.h> // needed for DMA interrupts

/************************************************************************************/
/* Reference data to process and check results                                      */
/************************************************************************************/

/** NIST-SP800-38B Appendix D.1 test vectors */
static const uint8_t keyData[16] = {
  0x2bu, 0x7eu, 0x15u, 0x16u, 0x28u, 0xaeu, 0xd2u, 0xa6u,
  0xabu, 0xf7u, 0x15u, 0x88u, 0x09u, 0xcfu, 0x4fu, 0x3cu
};

/************************************************************************************/
/* Helper code to synchronize example flow with nonBlocking background computation  */
/************************************************************************************/

#define MCUXCLMAC_STATUS_CALLBACK_NOT_EXECUTED ((uint32_t) 0xDEADBEEFu)
/* This variable is used to keep track of callbacks triggered by the non-blocking API. */
static volatile uint32_t macStatus_nonBlockingCallback = MCUXCLMAC_STATUS_CALLBACK_NOT_EXECUTED;

/* This function is called after the nonBlocking operation has finished */
static void user_callback(uint32_t status, void * data)
{
  (void)data;
  macStatus_nonBlockingCallback = status;
}

#define MCUXCLMAC_FLAG_DMA_INTERRUPT_NOT_TRIGGERED ((uint32_t) 0xDEADBEEFu)
/* This variable is a flag to notify the caller that an interrupt happened.
   It will contain the DMA channel ID of the respective channel that had an interrupt. */
static volatile uint32_t flag_interruptNumber = MCUXCLMAC_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;

/**************************************************************************/
/* Interrupt configuration code                                           */
/**************************************************************************/

/* Global resource context to handle status and session for the available HW resources.
   It shall be global and therefor only allocated once, for all sessions.
   Note that the examples create a "static" version of this global context, which is done
   solely to make sure examples are self-contained and do not conflict with each other. */
static uint32_t resourceContext[MCUXCLRESOURCE_CONTEXT_SIZE/sizeof(uint32_t)];
static mcuxClResource_Context_t * resourceCtxHandle = (mcuxClResource_Context_t *) &resourceContext;

/* This is the Interrupt handler for DMA done and error interrupts on the input channel.
   This function only sets the interrupt number as a global flag, the actual handler
   mcuxClResource_handle_interrupt needs to be called afterwards to wrap-up the CLib operation. */
static void handleDmaInterrupt_channel0(void)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_SFR_ACCESS()
  /* Clear DMA interrupt request status, W1C. Needed for DONE interrupts. */
  DMA0->CH[0].CH_INT = 1U;

  /* Clear the DMA error interrupt request status, W1C. Needed for ERROR interrupts. */
  uint32_t chCsr = DMA0->CH[0].CH_CSR;
  /* 1. Unset the DONE bit, to not accidentally perform a W1C. CLib needs this bit for internal checks. */
  chCsr &= ~((uint32_t)DMA_CH_CSR_DONE_MASK);
  /* 2. Clear the EEI bit. */
  chCsr &= ~((uint32_t)DMA_CH_CSR_EEI_MASK);
  /* 3. Write to CH_CSR */
  DMA0->CH[0].CH_CSR = chCsr;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SFR_ACCESS()

  flag_interruptNumber = GET_DMA_CHX_IRQ_NUMBER(0U);
}

/* Initialize (install, enable) the interrupts */
static void interruptInit(void)
{
  /* Enable interrupts for the input channel */
  mcuxClExample_OS_Interrupt_Callback_Install(handleDmaInterrupt_channel0, GET_DMA_CHX_IRQ_NUMBER(0U));

  /* Enable the interrupts in the controller */
  mcuxClExample_OS_Interrupt_Enable(GET_DMA_CHX_IRQ_NUMBER(0U));
}

/* Uninitialize (disable) the interrupts */
static void interruptUninit(void)
{
  /* Disable the interrupts in the controller */
  mcuxClExample_OS_Interrupt_Disable(GET_DMA_CHX_IRQ_NUMBER(0U));
}

/**************************************************************************/
/* Example for non-blocking CMAC multipart                                */
/*                                                                        */
/* The example shows which functions need to be called to configure the   */
/* non-blocking flow. Its important that the interrupt is triggered on    */
/* input channel. To show the non-blocking interrupt flow a polling-loop  */
/* is used to wait for the user-callback to be triggered by an interrupt. */
/**************************************************************************/
MCUXCLEXAMPLE_FUNCTION(mcuxClMacModes_Cmac_Aes128_Multipart_Dma_NonBlocking_example)
{
  /**************************************************************************/
  /* General Preparation                                                    */
  /**************************************************************************/

  /* Note: All DMA buffers needs to be on the stack because DMA cannot access ROM */
  const uint8_t data[80] = {
    0x6bu, 0xc1u, 0xbeu, 0xe2u, 0x2eu, 0x40u, 0x9fu, 0x96u,
    0xe9u, 0x3du, 0x7eu, 0x11u, 0x73u, 0x93u, 0x17u, 0x2au,
    0xaeu, 0x2du, 0x8au, 0x57u, 0x1eu, 0x03u, 0xacu, 0x9cu,
    0x9eu, 0xb7u, 0x6fu, 0xacu, 0x45u, 0xafu, 0x8eu, 0x51u,
    0x30u, 0xc8u, 0x1cu, 0x46u, 0xa3u, 0x5cu, 0xe4u, 0x11u,
    0x6bu, 0xc1u, 0xbeu, 0xe2u, 0x2eu, 0x40u, 0x9fu, 0x96u,
    0xe9u, 0x3du, 0x7eu, 0x11u, 0x73u, 0x93u, 0x17u, 0x2au,
    0xaeu, 0x2du, 0x8au, 0x57u, 0x1eu, 0x03u, 0xacu, 0x9cu,
    0x9eu, 0xb7u, 0x6fu, 0xacu, 0x45u, 0xafu, 0x8eu, 0x51u,
    0x30u, 0xc8u, 0x1cu, 0x46u, 0xa3u, 0x5cu, 0xe4u, 0x11u
  };

  static const uint8_t cmacReference[16] = {
    0xafu, 0xaeu, 0xb6u, 0xe1u, 0xb2u, 0xc1u, 0x7du, 0xe6u,
    0x8au, 0x25u, 0x52u, 0xb0u, 0xceu, 0x55u, 0xcdu, 0xd2u
  };

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION_NONBLOCKING(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLMAC_PROCESS_NONBLOCKING_CPU_WA_BUFFER_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0u);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  /* Initialize the key */
  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_status, ki_token, mcuxClKey_init(
    /* mcuxClSession_Handle_t session:        */ session,
    /* mcuxClKey_Handle_t key:                */ key,
    /* mcuxClKey_Type_t type:                 */ mcuxClKey_Type_Aes128,
    /* uint8_t * pKeyData:                   */ keyData,
    /* uint32_t keyDataLength:               */ sizeof(keyData))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) || (MCUXCLKEY_STATUS_OK != ki_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Non-Blocking Preparation                                               */
  /**************************************************************************/

  /* Enable DMA interrupt and set callback */
  interruptInit();

  /* Configure the DMA channels that should be used. For MAC operations, the two channels will never be used at the same time.
   * Use DMA channel 0 for both HW input and output operations. */
  mcuxClSession_Channels_t dmaChannels = {
    .input = (mcuxClSession_Channel_t) 0u,
    .output = (mcuxClSession_Channel_t) 0u
  };

  /* Set DMA channels and user callback function */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scj_status, scj_token, mcuxClSession_configure_job(
    /* mcuxClSession_Handle_t session:          */ session,
    /* mcuxClSession_Channels_t dmaChannels,    */ dmaChannels,
    /* mcuxClSession_Callback_t pUserCallback,  */ user_callback,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_NULL_POINTER_CONSTANT("NULL is used in code")
    /* void * pUserData                        */ NULL)
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NULL_POINTER_CONSTANT()
  );

  /* Initialize resource context and add it to the session */
  if(!mcuxClExample_Session_InitAndSetResourceCtx(session, resourceCtxHandle))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_configure_job) != scj_token) || (MCUXCLSESSION_STATUS_OK != scj_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* MAC Computation                                                        */
  /**************************************************************************/

  ALIGNED uint8_t ctxBuf[MCUXCLMAC_CONTEXT_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClMac_Context_t * ctx = (mcuxClMac_Context_t *) ctxBuf;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  uint8_t macData[sizeof(cmacReference)];

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mi_status, mi_token, mcuxClMac_init(
    /* mcuxClSession_Handle_t session:       */ session,
    /* mcuxClMac_Context_t * const pContext: */ ctx,
    /* const mcuxClKey_Handle_t key:         */ key,
    /* mcuxClMac_Mode_t mode:                */ mcuxClMac_Mode_CMAC_NonBlocking)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_init) != mi_token) || (MCUXCLMAC_STATUS_OK != mi_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_DMA_RO(dataBuf, session, data, sizeof(data));
  /* Multipart CMAC process */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mp1_status, mp1_token, mcuxClMac_process(
    /* mcuxClSession_Handle_t session:       */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClMac_init")
    /* mcuxClMac_Context_t * const pContext: */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:             */ dataBuf,
    /* uint32_t inLength:                   */ 5u     /* small amount of data, does not trigger a non-blocking operation */
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_process) != mp1_token) || ((MCUXCLMAC_STATUS_JOB_STARTED != mp1_status) && (MCUXCLMAC_STATUS_OK != mp1_status)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(MCUXCLMAC_STATUS_JOB_STARTED == mp1_status)
  {
    /* A non-blocking job was started. Wait for the interrupt */
    while(MCUXCLMAC_FLAG_DMA_INTERRUPT_NOT_TRIGGERED == flag_interruptNumber) {};

    /* Call the resource interrupt handler to finish the non-blocking operation.
     * On normal operation flow, this will trigger the user_callback function at the end,
     * which sets macStatus_nonBlockingCallback to the status code of the Mac operation.
     * On error, mcuxClResource_handle_interrupt returns an ERROR code without triggering
     * the user_callback. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rhi_status, rhi_token, mcuxClResource_handle_interrupt(resourceCtxHandle, flag_interruptNumber));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_handle_interrupt) != rhi_token) || (MCUXCLRESOURCE_STATUS_OK != rhi_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(MCUXCLMAC_STATUS_JOB_COMPLETED != macStatus_nonBlockingCallback)
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Reset polling loop condition and the status code */
    flag_interruptNumber = MCUXCLMAC_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;
    macStatus_nonBlockingCallback = MCUXCLMAC_STATUS_CALLBACK_NOT_EXECUTED;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_UPDATE(dataBuf, 5u);

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mp2_status, mp2_token, mcuxClMac_process(
    /* mcuxClSession_Handle_t session:       */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClMac_init")
    /* mcuxClMac_Context_t * const pContext: */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:             */ dataBuf,  /* Only part of input data was processed */
    /* uint32_t inLength:                   */ sizeof(data) - 5u  /* multiple blocks of data, triggers a non-blocking operation */
  ));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_process) != mp2_token) || ((MCUXCLMAC_STATUS_JOB_STARTED != mp2_status) && (MCUXCLMAC_STATUS_OK != mp2_status)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(MCUXCLMAC_STATUS_JOB_STARTED == mp2_status)
  {
    /* A non-blocking job was started. Wait for the interrupt */
    while(MCUXCLMAC_FLAG_DMA_INTERRUPT_NOT_TRIGGERED == flag_interruptNumber) {};

    /* Call the resource interrupt handler to finish the non-blocking operation.
     * On normal operation flow, this will trigger the user_callback function at the end,
     * which sets macStatus_nonBlockingCallback to the status code of the Mac operation.
     * On error, mcuxClResource_handle_interrupt returns an ERROR code without triggering
     * the user_callback. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rhi_status, rhi_token, mcuxClResource_handle_interrupt(resourceCtxHandle, flag_interruptNumber));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_handle_interrupt) != rhi_token) || (MCUXCLRESOURCE_STATUS_OK != rhi_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(MCUXCLMAC_STATUS_JOB_COMPLETED != macStatus_nonBlockingCallback)
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Reset polling loop condition and the status code */
    flag_interruptNumber = MCUXCLMAC_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;
    macStatus_nonBlockingCallback = MCUXCLMAC_STATUS_CALLBACK_NOT_EXECUTED;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  uint32_t macSize = 0u;

  MCUXCLBUFFER_INIT_DMA(macDataBuf, session, macData, sizeof(macData));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(mf_status, mf_token, mcuxClMac_finish(
    /* mcuxClSession_Handle_t session:       */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClMac_init")
    /* mcuxClMac_Context_t * const pContext: */ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_Buffer_t pMac:                 */ macDataBuf,
    /* uint32_t * const pMacLength:         */ &macSize)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_finish) != mf_token) || (MCUXCLMAC_STATUS_OK != mf_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Destroy the current session and clean-up                               */
  /**************************************************************************/

  if(!mcuxClExample_Session_Clean(session))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Disable the interrupts */
  interruptUninit();

  /**************************************************************************/
  /* Verification                                                           */
  /**************************************************************************/

  if (sizeof(cmacReference) != macSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if (!mcuxClCore_assertEqual(macData, cmacReference, sizeof(cmacReference)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
