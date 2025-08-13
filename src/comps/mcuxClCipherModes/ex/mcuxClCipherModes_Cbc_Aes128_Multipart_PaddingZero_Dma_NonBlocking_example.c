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
 * @example mcuxClCipherModes_Cbc_Aes128_Multipart_PaddingZero_Dma_NonBlocking_example.c
 * @brief   Example for the mcuxClCipherModes component
 */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClAes.h> // Interface to AES-related definitions and types
#include <mcuxClCipher.h> // Interface to the entire mcuxClCipher component
#include <mcuxClCipherModes.h> // Interface to the entire mcuxClCipherModes component
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

/* CBC encrypted data */
static const uint8_t encryptedRef[64] = {
    0xe6u, 0xd4u, 0xe7u, 0xdau, 0x9eu, 0x63u, 0xc6u, 0x67u,
    0xfbu, 0xa0u, 0x43u, 0x2au, 0xadu, 0x45u, 0x4bu, 0x7du,
    0xf2u, 0xb7u, 0x91u, 0x4eu, 0x89u, 0xe1u, 0x07u, 0xe1u,
    0xa0u, 0x0eu, 0xe2u, 0x52u, 0xccu, 0xbau, 0xbbu, 0x1fu,
    0x69u, 0x4au, 0x00u, 0xe4u, 0x2eu, 0x89u, 0xfbu, 0x43u,
    0x79u, 0x8bu, 0x28u, 0x38u, 0x6bu, 0x7cu, 0xecu, 0x7fu,
    0xd2u, 0x83u, 0xd6u, 0xabu, 0x01u, 0x38u, 0xe4u, 0xd0u,
    0xc8u, 0x41u, 0x99u, 0x55u, 0x5au, 0x1bu, 0xccu, 0x51u
};

/* Decrypted zero padded data */
static const uint8_t decryptedRef[64] = {
    0x61u, 0x62u, 0x63u, 0x64u, 0x65u, 0x66u, 0x67u, 0x68u,
    0x69u, 0x6Au, 0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u,
    0x62u, 0x63u, 0x64u, 0x65u, 0x66u, 0x67u, 0x68u, 0x69u,
    0x6Au, 0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u,
    0x63u, 0x64u, 0x65u, 0x66u, 0x67u, 0x68u, 0x69u, 0x6Au,
    0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u, 0x72u,
    0x64u, 0x65u, 0x66u, 0x67u, 0x68u, 0x69u, 0x6Au, 0x6Bu,
    0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u, 0x00u, 0x00u
};

static const uint8_t keyBytes[16] = {
    0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u, 0x72u,
    0x73u, 0x74u, 0x75u, 0x76u, 0x77u, 0x78u, 0x79u, 0x7Au,
};

/************************************************************************************/
/* Helper code to synchronize example flow with nonBlocking background computation  */
/************************************************************************************/

#define MCUXCLCIPHER_STATUS_CALLBACK_NOT_EXECUTED ((uint32_t) 0xDEADBEEFu)
/* This variable is used to keep track of callbacks triggered by the non-blocking API. */
static volatile uint32_t cipherStatus_nonBlockingCallback = MCUXCLCIPHER_STATUS_CALLBACK_NOT_EXECUTED;

/* This function is called after the nonBlocking operation has finished */
static void user_callback(uint32_t status, void * data)
{
  (void)data;
  cipherStatus_nonBlockingCallback = status;
}

#define MCUXCLCIPHER_FLAG_DMA_INTERRUPT_NOT_TRIGGERED ((uint32_t) 0xDEADBEEFu)
/* This variable is a flag to notify the caller that an interrupt happened.
   It will contain the DMA channel ID of the respective channel that had an interrupt. */
static volatile uint32_t flag_interruptNumber = MCUXCLCIPHER_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;

/**************************************************************************/
/* Interrupt configuration code                                           */
/**************************************************************************/

/* Global resource context to handle status and session for the available HW resources.
   It shall be global and therefor only allocated once, for all sessions.
   Note that the examples create a "static" version of this global context, which is done
   solely to make sure examples are self-contained and do not conflict with each other. */
/* TODO CLNS-16969: Use one global resource ctx for all examples */
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

  /* DMA_CH0 caused the interrupt */
  flag_interruptNumber = GET_DMA_CHX_IRQ_NUMBER(0U);
}

/* This is the Interrupt handler for DMA done and error interrupts on the output channel.
   This function only sets the interrupt number as a global flag, the actual handler
   mcuxClResource_handle_interrupt needs to be called afterwards to wrap-up the CLib operation. */
static void handleDmaInterrupt_channel1(void)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_SFR_ACCESS()
  /* Clear DMA interrupt request status, W1C. Needed for DONE interrupts. */
  DMA0->CH[1].CH_INT = 1U;

  /* Clear the DMA error interrupt request status, W1C. Needed for ERROR interrupts. */
  uint32_t chCsr = DMA0->CH[1].CH_CSR;
  /* 1. Unset the DONE bit, to not accidentally perform a W1C. CLib needs this bit for internal checks. */
  chCsr &= ~((uint32_t)DMA_CH_CSR_DONE_MASK);
  /* 2. Clear the EEI bit. */
  chCsr &= ~((uint32_t)DMA_CH_CSR_EEI_MASK);
  /* 3. Write to CH_CSR */
  DMA0->CH[1].CH_CSR = chCsr;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_SFR_ACCESS()

  /* DMA_CH1 caused the interrupt */
  flag_interruptNumber = GET_DMA_CHX_IRQ_NUMBER(1U);
}

/* Initialize (install, enable) the interrupts */
static void interruptInit(void)
{
  /* Enable interrupts for the input channel */
  mcuxClExample_OS_Interrupt_Callback_Install(handleDmaInterrupt_channel0, GET_DMA_CHX_IRQ_NUMBER(0U));

  /* Enable interrupts for the output channel */
  mcuxClExample_OS_Interrupt_Callback_Install(handleDmaInterrupt_channel1, GET_DMA_CHX_IRQ_NUMBER(1U));

  /* Enable the interrupts in the controller */
  mcuxClExample_OS_Interrupt_Enable(GET_DMA_CHX_IRQ_NUMBER(0U));
  mcuxClExample_OS_Interrupt_Enable(GET_DMA_CHX_IRQ_NUMBER(1U));
}

/* Uninitialize (disable) the interrupts */
static void interruptUninit(void)
{
  /* Disable the interrupts in the controller */
  mcuxClExample_OS_Interrupt_Disable(GET_DMA_CHX_IRQ_NUMBER(0U));
  mcuxClExample_OS_Interrupt_Disable(GET_DMA_CHX_IRQ_NUMBER(1U));
}

/***************************************************************************/
/* Example for non-blocking multipart ECB encryption and decryption        */
/* with zero padding                                                       */
/*                                                                         */
/* The example shows which functions need to be called to configure the    */
/* non-blocking flow. Its important that the interrupt is triggered on     */
/* input channel. To show the non-blocking interrupt flow a polling-loop   */
/* is used to wait for the user-callback to be triggered by an interrupt.  */
/***************************************************************************/
MCUXCLEXAMPLE_FUNCTION(mcuxClCipherModes_Cbc_Aes128_Multipart_PaddingZero_Dma_NonBlocking_example)
{
  /**************************************************************************/
  /* General Preparation                                                    */
  /**************************************************************************/

  /* Enable DMA interrupt and set callback */
  interruptInit();

  /* Note: input buffer needs to be on the stack because DMA cannot access ROM */
  const uint8_t plain[62] = {
    0x61u, 0x62u, 0x63u, 0x64u, 0x65u, 0x66u, 0x67u, 0x68u,
    0x69u, 0x6Au, 0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u,
    0x62u, 0x63u, 0x64u, 0x65u, 0x66u, 0x67u, 0x68u, 0x69u,
    0x6Au, 0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u,
    0x63u, 0x64u, 0x65u, 0x66u, 0x67u, 0x68u, 0x69u, 0x6Au,
    0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u, 0x72u,
    0x64u, 0x65u, 0x66u, 0x67u, 0x68u, 0x69u, 0x6Au, 0x6Bu,
    0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u
  };

  const uint8_t iv[16] = {
      0x7Au, 0x79u, 0x78u, 0x77u, 0x76u, 0x75u, 0x74u, 0x73u,
      0x72u, 0x71u, 0x70u, 0x6Fu, 0x6Eu, 0x6Du, 0x6Cu, 0x6Bu,
  };

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;


  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION_NONBLOCKING(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHER_AES_PROCESS_CPU_WA_BUFFER_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0u);

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
    /* uint8_t * pKeyData:                   */ keyBytes,
    /* uint32_t keyDataLength:               */ sizeof(keyBytes))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_token) || (MCUXCLKEY_STATUS_OK != ki_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Non-Blocking Preparation                                               */
  /**************************************************************************/

  /* Configure the DMA channels that should be used.
   * Use DMA channel 0 for HW input operations, and DMA channel 1 for HW output operations */
  mcuxClSession_Channels_t dmaChannels = {
    .input = (mcuxClSession_Channel_t) 0u,
    .output = (mcuxClSession_Channel_t) 1u
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
  /* Encryption                                                             */
  /**************************************************************************/

  uint32_t outLength = 0u;
  uint32_t encryptedSize = 0u;
  uint8_t encryptedData[sizeof(encryptedRef)] = {0u};

  /* Create a buffer for the context */
  ALIGNED uint8_t ctxBuf[MCUXCLCIPHER_AES_CONTEXT_SIZE];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClCipher_Context_t * const ctx = (mcuxClCipher_Context_t *) ctxBuf;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

  MCUXCLBUFFER_INIT_DMA_RO(ivBuf, session, iv, sizeof(iv));
  /* Multipart encrypt init */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ei_status, ei_token, mcuxClCipher_init_encrypt(
    /* mcuxClSession_Handle_t session:         */ session,
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    /* const mcuxClKey_Handle_t key:           */ key,
    /* mcuxClCipher_Mode_t mode:               */ mcuxClCipher_Mode_AES_CBC_PaddingISO9797_1_Method1_NonBlocking,
    /* mcuxCl_InputBuffer_t pIv:               */ ivBuf,
    /* uint32_t ivLength:                     */ sizeof(iv))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_init_encrypt) != ei_token) || (MCUXCLCIPHER_STATUS_OK != ei_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUXCLBUFFER_INIT_DMA_RO(plainBuf, session, plain, sizeof(plain));
  MCUXCLBUFFER_INIT_DMA(encryptedDataBuf, session, encryptedData, sizeof(encryptedData));
  /* Multipart encrypt process */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ep1_status, ep1_token, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_encrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:               */ plainBuf,
    /* uint32_t inLength:                     */ sizeof(plain),
    /* mcuxCl_Buffer_t pOut:                   */ encryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != ep1_token) || ((MCUXCLCIPHER_STATUS_JOB_STARTED != ep1_status) && (MCUXCLCIPHER_STATUS_OK != ep1_status)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(MCUXCLCIPHER_STATUS_JOB_STARTED == ep1_status)
  {
    /* A non-blocking job was started. Wait for the interrupt */
    while(MCUXCLCIPHER_FLAG_DMA_INTERRUPT_NOT_TRIGGERED == flag_interruptNumber) {};

    /* Call the resource interrupt handler to finish the non-blocking operation.
     * On normal operation flow, this will trigger the user_callback function at the end,
     * which sets cipherStatus_nonBlockingCallback to the status code of the Cipher operation.
     * On error, mcuxClResource_handle_interrupt returns an ERROR code without triggering
     * the user_callback. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rhi_status, rhi_token, mcuxClResource_handle_interrupt(resourceCtxHandle, flag_interruptNumber));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_handle_interrupt) != rhi_token) || (MCUXCLRESOURCE_STATUS_OK != rhi_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(MCUXCLCIPHER_STATUS_JOB_COMPLETED != cipherStatus_nonBlockingCallback)
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Reset polling loop condition and the status code */
    flag_interruptNumber = MCUXCLCIPHER_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;
    cipherStatus_nonBlockingCallback = MCUXCLCIPHER_STATUS_CALLBACK_NOT_EXECUTED;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  encryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUXCLBUFFER_UPDATE(encryptedDataBuf, encryptedSize);
  /* Multipart encrypt finish */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ef_status, ef_token, mcuxClCipher_finish(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_encrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_Buffer_t pOut:                   */ encryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_finish) != ef_token) || (MCUXCLCIPHER_STATUS_OK != ef_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  encryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  /**************************************************************************/
  /* Decryption                                                             */
  /**************************************************************************/

  uint32_t decryptedSize = 0u;
  uint8_t decryptedData[sizeof(decryptedRef)];

  /* Multipart decrypt init */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(di_status, di_token, mcuxClCipher_init_decrypt(
    /* mcuxClSession_Handle_t session:         */ session,
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    /* const mcuxClKey_Handle_t key:           */ key,
    /* mcuxClCipher_Mode_t mode:               */ mcuxClCipher_Mode_AES_CBC_PaddingISO9797_1_Method1_NonBlocking,
    /* mcuxCl_InputBuffer_t pIv:               */ ivBuf,
    /* uint32_t ivLength:                     */ sizeof(iv))
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_init_decrypt) != di_token) || (MCUXCLCIPHER_STATUS_OK != di_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Process again from the beginning of encryptedDataBuf */
  MCUXCLBUFFER_SET(encryptedDataBuf, encryptedData, sizeof(encryptedData) /* unused */);
  MCUXCLBUFFER_INIT_DMA(decryptedDataBuf, session, decryptedData, sizeof(decryptedData));
 /* Multipart decrypt process */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(dp1_status, dp1_token, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_decrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_InputBuffer_t pIn:               */ (mcuxCl_InputBuffer_t) encryptedDataBuf,
    /* uint32_t inLength:                     */ encryptedSize,
    /* mcuxCl_Buffer_t pOut:                   */ decryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != dp1_token) || ((MCUXCLCIPHER_STATUS_JOB_STARTED != dp1_status) && (MCUXCLCIPHER_STATUS_OK != dp1_status)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(MCUXCLCIPHER_STATUS_JOB_STARTED == dp1_status)
  {
    /* A non-blocking job was started. Wait for the interrupt */
    while(MCUXCLCIPHER_FLAG_DMA_INTERRUPT_NOT_TRIGGERED == flag_interruptNumber) {};

    /* Call the resource interrupt handler to finish the non-blocking operation.
     * On normal operation flow, this will trigger the user_callback function at the end,
     * which sets cipherStatus_nonBlockingCallback to the status code of the Cipher operation.
     * On error, mcuxClResource_handle_interrupt returns an ERROR code without triggering
     * the user_callback. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rhi_status, rhi_token, mcuxClResource_handle_interrupt(resourceCtxHandle, flag_interruptNumber));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_handle_interrupt) != rhi_token) || (MCUXCLRESOURCE_STATUS_OK != rhi_status))
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(MCUXCLCIPHER_STATUS_JOB_COMPLETED != cipherStatus_nonBlockingCallback)
    {
      return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Reset polling loop condition and the status code */
    flag_interruptNumber = MCUXCLCIPHER_FLAG_DMA_INTERRUPT_NOT_TRIGGERED;
    cipherStatus_nonBlockingCallback = MCUXCLCIPHER_STATUS_CALLBACK_NOT_EXECUTED;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  decryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUXCLBUFFER_UPDATE(decryptedDataBuf, decryptedSize);
  /* Multipart decrypt finish */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(df_status, df_token, mcuxClCipher_finish(
    /* mcuxClSession_Handle_t session:         */ session,
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClCipher_init_decrypt")
    /* mcuxClCipher_Context_t * const pContext:*/ ctx,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* mcuxCl_Buffer_t pOut:                   */ decryptedDataBuf,
    /* uint32_t * const outLength:            */ &outLength)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_finish) != df_token) || (MCUXCLCIPHER_STATUS_OK != df_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  decryptedSize += outLength;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

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

  if(sizeof(encryptedRef) != encryptedSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT_DMA")
  if(!mcuxClCore_assertEqual(encryptedRef, encryptedData, sizeof(encryptedRef)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  if(sizeof(decryptedRef) != decryptedSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT_DMA")
  if(!mcuxClCore_assertEqual(decryptedRef, decryptedData, sizeof(decryptedRef)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  return MCUXCLEXAMPLE_STATUS_OK;
}

