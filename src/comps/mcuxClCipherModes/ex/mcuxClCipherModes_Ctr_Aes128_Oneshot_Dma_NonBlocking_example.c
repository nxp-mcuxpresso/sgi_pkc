/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
/*--------------------------------------------------------------------------*/

/**
 * @example mcuxClCipherModes_Ctr_Aes128_Oneshot_Dma_NonBlocking_example.c
 * @brief   Example for the mcuxClCipherModes component
 */

#include <mcuxClSession.h>
#include <mcuxClResource.h>
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

/* These example vectors are taken from NIST Special Publication 800-38A, 2001 Edition. */

/* CTR encrypted data */
static const uint8_t encryptedRef[64] = {
  0x87U, 0x4dU, 0x61U, 0x91U, 0xb6U, 0x20U, 0xe3U, 0x26U,
  0x1bU, 0xefU, 0x68U, 0x64U, 0x99U, 0x0dU, 0xb6U, 0xceU,
  0x98U, 0x06U, 0xf6U, 0x6bU, 0x79U, 0x70U, 0xfdU, 0xffU,
  0x86U, 0x17U, 0x18U, 0x7bU, 0xb9U, 0xffU, 0xfdU, 0xffU,
  0x5aU, 0xe4U, 0xdfU, 0x3eU, 0xdbU, 0xd5U, 0xd3U, 0x5eU,
  0x5bU, 0x4fU, 0x09U, 0x02U, 0x0dU, 0xb0U, 0x3eU, 0xabU,
  0x1eU, 0x03U, 0x1dU, 0xdaU, 0x2fU, 0xbeU, 0x03U, 0xd1U,
  0x79U, 0x21U, 0x70U, 0xa0U, 0xf3U, 0x00U, 0x9cU, 0xeeU
};

/* AES key for encrypting/ decrypting the data */
static const uint8_t keyBytes[16] = {
  0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
  0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
};

/************************************************************************************/
/* Helper code to synchronize example flow with nonBlocking background computation  */
/************************************************************************************/

#define MCUXCLCIPHER_STATUS_CALLBACK_NOT_EXECUTED ((uint32_t) 0xDEADBEEFU)
/* This variable is used to keep track of callbacks triggered by the non-blocking API. */
static volatile uint32_t cipherStatus_nonBlockingCallback = MCUXCLCIPHER_STATUS_CALLBACK_NOT_EXECUTED;

/* This function is called after the nonBlocking operation has finished */
static void user_callback(uint32_t status, void * data)
{
  (void)data;
  cipherStatus_nonBlockingCallback = status;
}

#define MCUXCLCIPHER_FLAG_DMA_INTERRUPT_NOT_TRIGGERED ((uint32_t) 0xDEADBEEFU)
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

/**************************************************************************/
/* Example for non-blocking CTR encryption and decryption                 */
/*                                                                        */
/* The example shows which functions need to be called to configure the   */
/* non-blocking flow. Its important that the interrupt is triggered on    */
/* input channel. To show the non-blocking interrupt flow a polling-loop  */
/* is used to wait for the user-callback to be triggered by an interrupt. */
/**************************************************************************/
MCUXCLEXAMPLE_FUNCTION(mcuxClCipherModes_Ctr_Aes128_Oneshot_Dma_NonBlocking_example)
{
  /**************************************************************************/
  /* General Preparation                                                    */
  /**************************************************************************/

  /* Enable DMA interrupt and set callback */
  interruptInit();

  /* Note: input buffer needs to be on the stack because DMA cannot access ROM */
  const uint8_t plain[64] = {
    0x6bU, 0xc1U, 0xbeU, 0xe2U, 0x2eU, 0x40U, 0x9fU, 0x96U,
    0xe9U, 0x3dU, 0x7eU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2aU,
    0xaeU, 0x2dU, 0x8aU, 0x57U, 0x1eU, 0x03U, 0xacU, 0x9cU,
    0x9eU, 0xb7U, 0x6fU, 0xacU, 0x45U, 0xafU, 0x8eU, 0x51U,
    0x30U, 0xc8U, 0x1cU, 0x46U, 0xa3U, 0x5cU, 0xe4U, 0x11U,
    0xe5U, 0xfbU, 0xc1U, 0x19U, 0x1aU, 0x0aU, 0x52U, 0xefU,
    0xf6U, 0x9fU, 0x24U, 0x45U, 0xdfU, 0x4fU, 0x9bU, 0x17U,
    0xadU, 0x2bU, 0x41U, 0x7bU, 0xe6U, 0x6cU, 0x37U, 0x10U
  };

  /* Note: input bUffer needs to be on the stack because DMA cannot access ROM */
  const uint8_t iv[16] = {
    0xf0U, 0xf1U, 0xf2U, 0xf3U, 0xf4U, 0xf5U, 0xf6U, 0xf7U,
    0xf8U, 0xf9U, 0xfaU, 0xfbU, 0xfcU, 0xfdU, 0xfeU, 0xffU
  };

  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;

  /* Allocate and initialize session */
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION_NONBLOCKING(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHER_MAX_AES_CPU_WA_BUFFER_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0U);

  /* Initialize the PRNG */
  MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

  /* Initialize the key */
  uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;
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
    .input = (mcuxClSession_Channel_t) 0U,
    .output = (mcuxClSession_Channel_t) 1U
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

  uint32_t encryptedSize = 0U;
  uint8_t encryptedData[sizeof(encryptedRef)];

  MCUXCLBUFFER_INIT_DMA_RO(ivBuf, session, iv, sizeof(iv));
  MCUXCLBUFFER_INIT_DMA_RO(plainBuf, session, plain, sizeof(plain));
  MCUXCLBUFFER_INIT_DMA(encryptedDataBuf, session, encryptedData, sizeof(encryptedData));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(e_status, e_token, mcuxClCipher_encrypt(
    /* mcuxClSession_Handle_t session:         */ session,
    /* const mcuxClKey_Handle_t key:           */ key,
    /* mcuxClCipher_Mode_t mode:               */ mcuxClCipher_Mode_AES_CTR_NonBlocking,
    /* mcuxCl_InputBuffer_t pIv:               */ ivBuf,
    /* uint32_t ivLength:                     */ sizeof(iv),
    /* mcuxCl_InputBuffer_t pIn:               */ plainBuf,
    /* uint32_t inLength:                     */ sizeof(plain),
    /* mcuxCl_Buffer_t pOut:                   */ encryptedDataBuf,
    /* uint32_t * const outLength:            */ &encryptedSize) /* only relevant in case of padding being used */
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_encrypt) != e_token) || ((MCUXCLCIPHER_STATUS_JOB_STARTED != e_status) && (MCUXCLCIPHER_STATUS_OK != e_status)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(MCUXCLCIPHER_STATUS_JOB_STARTED == e_status)
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

  /**************************************************************************/
  /* Decryption                                                             */
  /**************************************************************************/

  uint32_t decryptedSize = 0U;
  uint8_t decryptedData[sizeof(plain)];

  MCUXCLBUFFER_INIT_DMA(decryptedDataBuf, session, decryptedData, sizeof(decryptedData));
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(d_status, d_token, mcuxClCipher_decrypt(
    /* mcuxClSession_Handle_t session:        */ session,
    /* const mcuxClKey_Handle_t key:          */ key,
    /* mcuxClCipher_Mode_t mode:              */ mcuxClCipher_Mode_AES_CTR_NonBlocking,
    /* mcuxCl_InputBuffer_t pIv:              */ ivBuf,
    /* uint32_t ivLength:                    */ sizeof(iv),
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT_DMA")
    /* const mcuxCl_InputBuffer_t pIn:        */ (mcuxCl_InputBuffer_t) encryptedDataBuf,
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
    /* uint32_t inLength:                    */ encryptedSize,
    /* mcuxCl_Buffer_t pOut:                  */ decryptedDataBuf,
    /* uint32_t * const outLength:           */ &decryptedSize) /* only relevant in case of padding being used/removed */
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_decrypt) != d_token) || ((MCUXCLCIPHER_STATUS_JOB_STARTED != d_status) && (MCUXCLCIPHER_STATUS_OK != d_status)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  if(MCUXCLCIPHER_STATUS_JOB_STARTED == d_status)
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

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("encryptedData initialized by mcuxClCipher_encrypt")
  if(!mcuxClCore_assertEqual(encryptedRef, encryptedData, sizeof(encryptedRef)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  if(sizeof(plain) != decryptedSize)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("decryptedData initialized by mcuxClCipher_decrypt")
  if(!mcuxClCore_assertEqual(plain, decryptedData, sizeof(plain)))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()

  return MCUXCLEXAMPLE_STATUS_OK;
}
