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
 * @example mcuxClHashModes_sha256_streaming_dma_nonBlocking_example.c
 * @brief mcuxClHashModes example application
 */

#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxClHash.h>             // Interface to the entire mcuxClHash component
#include <mcuxClHashModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClToolchain.h>             // memory segment definitions
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_OS.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_RNG_Helper.h>

#include <platform_specific_headers.h> // needed for DMA interrupts

static const uint8_t longHashExpected[MCUXCLHASH_OUTPUT_SIZE_SHA_256] = {
    0x3cu, 0x59u, 0x3au, 0xa5u, 0x39u, 0xfdu, 0xcdu, 0xaeu,
    0x51u, 0x6cu, 0xdfu, 0x2fu, 0x15u, 0x00u, 0x0fu, 0x66u,
    0x34u, 0x18u, 0x5cu, 0x88u, 0xf5u, 0x05u, 0xb3u, 0x97u,
    0x75u, 0xfbu, 0x9au, 0xb1u, 0x37u, 0xa1u, 0x0au, 0xa2u
};

/************************************************************************************/
/* Helper code to synchronize example flow with nonBlocking background computation  */
/************************************************************************************/

#define MCUXCLHASH_STATUS_CALLBACK_NOT_EXECUTED ((uint32_t) 0xDEADBEEFu)
/* This variable is used to keep track of callbacks triggered by the non-blocking API. */
volatile uint32_t sha2MultipartnonBlockingStatus_callback = MCUXCLHASH_STATUS_CALLBACK_NOT_EXECUTED;

#define MCUXCLHASH_FLAG_DMA_INTERRUPT_NOT_TRIGGERED ((uint32_t) 0xDEADBEEFu)
/* This variable is a flag to notify the caller that an interrupt happened.
   It will contain the IRQ number associated with the DMA channel ID of the respective channel that had an interrupt. */
static volatile uint32_t flag_interruptNumber = MCUXCLHASH_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;

/* This function is called after the nonBlocking operation has finished */
static void user_callback(uint32_t status, void * data)
{
  (void)data;
  sha2MultipartnonBlockingStatus_callback = status;
}

/**************************************************************************/
/* Interrupt configuration code                                           */
/**************************************************************************/
// TODO-CLNS-16969: fix global resourceCtx
/* Global resource context to handle status and session for the available hw resources
   As it is global it should be only allocated once */
static uint32_t resourceContext[MCUXCLRESOURCE_CONTEXT_SIZE/sizeof(uint32_t)];
static mcuxClResource_Context_t * resourceCtxHandle = (mcuxClResource_Context_t *) &resourceContext;

/* This is the Interrupt handler for DMA done and error interrupts on the input channel.
   This function only sets the interrupt number as a global flag, the actual handler
   mcuxClResource_handle_interrupt needs to be called afterwards to wrap-up the CLib operation. */
static void handleDmaInterrupt_channel0(void)
{
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

  flag_interruptNumber = GET_DMA_CHX_IRQ_NUMBER(0);
}

/* Initialize (install, enable) the interrupts */
static void interruptInit(void)
{
  /* Enable interrupts for the input channel */
  mcuxClExample_OS_Interrupt_Callback_Install(handleDmaInterrupt_channel0, GET_DMA_CHX_IRQ_NUMBER(0));

  /* Enable the interrupts in the controller */
  mcuxClExample_OS_Interrupt_Enable(GET_DMA_CHX_IRQ_NUMBER(0));
}

/* Uninitialize (disable) the interrupts */
static void interruptUninit(void)
{
  /* Disable the interrupts in the controller */
  mcuxClExample_OS_Interrupt_Disable(GET_DMA_CHX_IRQ_NUMBER(0));
}

MCUXCLEXAMPLE_FUNCTION(mcuxClHashModes_sha256_streaming_dma_nonBlocking_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /* Test vector from CAVS 11.0 "SHA-256 LongMsg" */
  uint8_t data1[] = {
    0x45u, 0x11u, 0x01u, 0x25u, 0x0eu, 0xc6u, 0xf2u, 0x66u,
    0x52u, 0x24u, 0x9du, 0x59u, 0xdcu, 0x97u, 0x4bu, 0x73u,
    0x61u, 0xd5u, 0x71u, 0xa8u, 0x10u, 0x1cu, 0xdfu, 0xd3u,
    0x6au, 0xbau, 0x3bu, 0x58u, 0x54u, 0xd3u, 0xaeu, 0x08u,
    0x6bu, 0x5fu, 0xddu, 0x45u, 0x97u, 0x72u, 0x1bu, 0x66u,
    0xe3u, 0xc0u, 0xdcu, 0x5du, 0x8cu, 0x60u, 0x6du, 0x96u,
    0x57u, 0xd0u, 0xe3u, 0x23u, 0x28u, 0x3au, 0x52u, 0x17u,
    0xd1u, 0xf5u, 0x3fu, 0x2fu, 0x28u, 0x4fu, 0x57u, 0xb8u
  };

  uint8_t data2[] = {
    0x5cu, 0x8au, 0x61u, 0xacu, 0x89u, 0x24u, 0x71u, 0x1fu
  };

  uint8_t data3[] = {
    0x89u, 0x5cu, 0x5eu, 0xd9u, 0x0eu, 0xf1u, 0x77u, 0x45u,
    0xedu, 0x2du, 0x72u, 0x8au, 0xbdu, 0x22u, 0xa5u, 0xf7u,
    0xa1u, 0x34u, 0x79u, 0xa4u, 0x62u, 0xd7u, 0x1bu, 0x56u,
    0xc1u, 0x9au, 0x74u, 0xa4u, 0x0bu, 0x65u, 0x5cu, 0x58u,
    0xedu, 0xfeu, 0x0au, 0x18u, 0x8au, 0xd2u, 0xcfu, 0x46u,
    0xcbu, 0xf3u, 0x05u, 0x24u, 0xf6u, 0x5du, 0x42u, 0x3cu,
    0x83u, 0x7du, 0xd1u, 0xffu, 0x2bu, 0xf4u, 0x62u, 0xacu,
    0x41u, 0x98u
  };

  uint8_t data4[] = {
    0x00u, 0x73u, 0x45u, 0xbbu, 0x44u, 0xdbu,
    0xb7u, 0xb1u, 0xc8u, 0x61u, 0x29u, 0x8cu, 0xdfu, 0x61u,
    0x98u, 0x2au, 0x83u, 0x3au, 0xfcu, 0x72u, 0x8fu
  };

  uint8_t data5[] = {
    0xaeu, 0x1eu, 0xdau, 0x2fu, 0x87u, 0xaau, 0x2cu, 0x94u, 0x80u,
    0x85u, 0x8bu, 0xecu
  };

  /* Enable DMA interrupt and set callback */
  interruptInit();
  /* Set status of pooling variable to not executed */
  sha2MultipartnonBlockingStatus_callback = MCUXCLHASH_STATUS_CALLBACK_NOT_EXECUTED;

  /* Initialize session */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(
      session,
      MCUXCLEXAMPLE_MAX_WA(MCUXCLHASH_PROCESS_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_256,
        MCUXCLEXAMPLE_MAX_WA(MCUXCLHASH_FINISH_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_256,
                          MCUXCLRANDOM_NCINIT_WACPU_SIZE)),
      0u);

    /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  /* Configure the DMA channels that should be used. For Sha2 operations, the two channels will never be used at the same time.
   * Use DMA channel 0 for HW input operations. */
  mcuxClSession_Channels_t dmaChannels = {
    .input = (mcuxClSession_Channel_t) 0u,
    .output = (mcuxClSession_Channel_t) 0u
  };

  /* Set DMA channels and user callback function */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scj_status, scj_token, mcuxClSession_configure_job(
    /* mcuxClSession_Handle_t session:          */ session,
    /* mcuxClSession_Channels_t dmaChannels,    */ dmaChannels,
    /* mcuxClSession_Callback_t pUserCallback,  */ user_callback,
    /* void * pUserData                        */ NULL)
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

  uint32_t context[MCUXCLHASH_CONTEXT_SIZE_SHA2_256_IN_WORDS];

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result2, token2, mcuxClHash_init(
  /* mcuxCLSession_Handle_t session: */ session,
  /* mcuxClHash_Context_t context:   */ (mcuxClHash_Context_t) context,
  /* mcuxClHash_Algo_t algorithm:    */ mcuxClHash_Algorithm_Sha256_Dma_NonBlocking
  ));
  // mcuxClHash_init is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init) != token2) || (MCUXCLHASH_STATUS_OK != result2))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_DMA_RO(data1Buf, session, data1, sizeof(data1));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result3, token3, mcuxClHash_process(
  /* mcuxCLSession_Handle_t session: */ session,
  /* mcuxClHash_Context_t context:   */ (mcuxClHash_Context_t) context,
  /* mcuxCl_InputBuffer_t in:        */ data1Buf,
  /* uint32_t inSize:               */ sizeof(data1)
  ));
  // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token3))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if (MCUXCLHASH_STATUS_JOB_STARTED == result3)
  {
    /* A non-blocking job was started. Wait for the interrupt. */
    while(MCUXCLHASH_FLAG_DMA_INTERRUPT_NOT_TRIGGERED == flag_interruptNumber) {};

    /* Call the resource interrupt handler to finish the non-blocking operation.
     * On normal operation flow, this will trigger the user_callback function at the end,
     * which sets hashAPInonBlockingStatus_callback to the status code of the Hash operation.
     * On error, mcuxClResource_handle_interrupt returns an ERROR code without triggering
     * the user_callback. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rhi_status, rhi_token, mcuxClResource_handle_interrupt(resourceCtxHandle, flag_interruptNumber));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_handle_interrupt) != rhi_token) || (MCUXCLRESOURCE_STATUS_OK != rhi_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(MCUXCLHASH_STATUS_JOB_COMPLETED != sha2MultipartnonBlockingStatus_callback)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Reset polling loop condition and the status code */
    flag_interruptNumber = MCUXCLHASH_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;
    sha2MultipartnonBlockingStatus_callback = MCUXCLHASH_STATUS_CALLBACK_NOT_EXECUTED;
  }
  else if (MCUXCLHASH_STATUS_OK != result3)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  else
  {
    /* Entering here means that all operations executed successfully without starting non-blocking job,
       Here no action is required and we can continue. */
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_DMA_RO(data2Buf, session, data2, sizeof(data2));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result4, token4, mcuxClHash_process(
  /* mcuxCLSession_Handle_t session: */ session,
  /* mcuxClHash_Context_t context:   */ (mcuxClHash_Context_t) context,
  /* mcuxCl_InputBuffer_t in:        */ data2Buf,
  /* uint32_t inSize:               */ sizeof(data2)
  ));
  // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token4))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if (MCUXCLHASH_STATUS_JOB_STARTED == result4)
  {
    /* A non-blocking job was started. Wait for the interrupt. */
    while(MCUXCLHASH_FLAG_DMA_INTERRUPT_NOT_TRIGGERED == flag_interruptNumber) {};

    /* Call the resource interrupt handler to finish the non-blocking operation.
     * On normal operation flow, this will trigger the user_callback function at the end,
     * which sets hashAPInonBlockingStatus_callback to the status code of the Hash operation.
     * On error, mcuxClResource_handle_interrupt returns an ERROR code without triggering
     * the user_callback. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rhi_status, rhi_token, mcuxClResource_handle_interrupt(resourceCtxHandle, flag_interruptNumber));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_handle_interrupt) != rhi_token) || (MCUXCLRESOURCE_STATUS_OK != rhi_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(MCUXCLHASH_STATUS_JOB_COMPLETED != sha2MultipartnonBlockingStatus_callback)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Reset polling loop condition and the status code */
    flag_interruptNumber = MCUXCLHASH_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;
    sha2MultipartnonBlockingStatus_callback = MCUXCLHASH_STATUS_CALLBACK_NOT_EXECUTED;
  }
  else if (MCUXCLHASH_STATUS_OK != result4)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  else
  {
    /* Entering here means that all operations executed successfully without starting non-blocking job,
       Here no action is required and we can continue. */
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_DMA_RO(data3Buf, session, data3, sizeof(data3));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result5, token5, mcuxClHash_process(
  /* mcuxCLSession_Handle_t session: */ session,
  /* mcuxClHash_Context_t context:   */ (mcuxClHash_Context_t) context,
  /* mcuxCl_InputBuffer_t in:        */ data3Buf,
  /* uint32_t inSize:               */ sizeof(data3)
  ));
  // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token5))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if (MCUXCLHASH_STATUS_JOB_STARTED == result5)
  {
    /* A non-blocking job was started. Wait for the interrupt. */
    while(MCUXCLHASH_FLAG_DMA_INTERRUPT_NOT_TRIGGERED == flag_interruptNumber) {};

    /* Call the resource interrupt handler to finish the non-blocking operation.
     * On normal operation flow, this will trigger the user_callback function at the end,
     * which sets hashAPInonBlockingStatus_callback to the status code of the Hash operation.
     * On error, mcuxClResource_handle_interrupt returns an ERROR code without triggering
     * the user_callback. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rhi_status, rhi_token, mcuxClResource_handle_interrupt(resourceCtxHandle, flag_interruptNumber));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_handle_interrupt) != rhi_token) || (MCUXCLRESOURCE_STATUS_OK != rhi_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(MCUXCLHASH_STATUS_JOB_COMPLETED != sha2MultipartnonBlockingStatus_callback)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Reset polling loop condition and the status code */
    flag_interruptNumber = MCUXCLHASH_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;
    sha2MultipartnonBlockingStatus_callback = MCUXCLHASH_STATUS_CALLBACK_NOT_EXECUTED;
  }
  else if (MCUXCLHASH_STATUS_OK != result5)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  else
  {
    /* Entering here means that all operations executed successfully without starting non-blocking job,
       Here no action is required and we can continue. */
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_DMA_RO(data4Buf, session, data4, sizeof(data4));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result6, token6, mcuxClHash_process(
  /* mcuxCLSession_Handle_t session: */ session,
  /* mcuxClHash_Context_t context:   */ (mcuxClHash_Context_t) context,
  /* mcuxCl_InputBuffer_t in:        */ data4Buf,
  /* uint32_t inSize:               */ sizeof(data4)
  ));
  // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token6))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if (MCUXCLHASH_STATUS_JOB_STARTED == result6)
  {
    /* A non-blocking job was started. A polling loop is used to wait for the user callback. */
    while(MCUXCLHASH_STATUS_CALLBACK_NOT_EXECUTED == sha2MultipartnonBlockingStatus_callback) {};
  }
  else if (MCUXCLHASH_STATUS_OK != result6)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  else
  {
    /* Entering here means that all operations executed successfully without starting non-blocking job,
       Here no action is required and we can continue. */
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_DMA_RO(data5Buf, session, data5, sizeof(data5));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result7, token7, mcuxClHash_process(
  /* mcuxCLSession_Handle_t session: */ session,
  /* mcuxClHash_Context_t context:   */ (mcuxClHash_Context_t) context,
  /* mcuxCl_InputBuffer_t in:        */ data5Buf,
  /* uint32_t inSize:               */ sizeof(data5)
  ));
  // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token7))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if (MCUXCLHASH_STATUS_JOB_STARTED == result7)
  {
    /* A non-blocking job was started. A polling loop is used to wait for the user callback. */
    while(MCUXCLHASH_STATUS_CALLBACK_NOT_EXECUTED == sha2MultipartnonBlockingStatus_callback) {};
  }
  else if (MCUXCLHASH_STATUS_OK != result7)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  else
  {
    /* Entering here means that all operations executed successfully without starting non-blocking job,
       Here no action is required and we can continue. */
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  ALIGNED uint8_t hash[MCUXCLHASH_OUTPUT_SIZE_SHA_256];
  uint32_t hashOutputSize = 0u;

  MCUXCLBUFFER_INIT_DMA_RW(hashBuf, session, hash, sizeof(hash));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result8, token8, mcuxClHash_finish(
  /* mcuxCLSession_Handle_t session: */ session,
  /* mcuxClHash_Context_t context:   */ (mcuxClHash_Context_t) context,
    /* mcuxCl_Buffer_t pOut            */ hashBuf,
    /* uint32_t *const pOutSize,      */ &hashOutputSize
  ));
  // mcuxClHash_finish is a flow-protected function: Check the protection token and the return value
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish) != token8) || (MCUXCLHASH_STATUS_OK != result8))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  if(sizeof(hash) != hashOutputSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /**************************************************************************/
  /* Verification                                                           */
  /**************************************************************************/
  for (size_t i = 0U; i < sizeof(hash); i++)
  {
    if (longHashExpected[i] != hash[i]) // Expect that the resulting hash matches our expected output
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
  }

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Disable the interrupts */
    interruptUninit();

    return MCUXCLEXAMPLE_STATUS_OK;
}
