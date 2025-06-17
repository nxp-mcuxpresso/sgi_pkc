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

#ifndef MCUXCLCIPHERMODES_COMMON_WA_H_
#define MCUXCLCIPHERMODES_COMMON_WA_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClCipher_Types.h>
#include <internal/mcuxClCipherModes_Common_Constants.h>
#include <mcuxClAes.h>
#include <internal/mcuxClAes_Wa.h>
#include <internal/mcuxClAes_Internal_Constants.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClKey_Types_Internal.h>

/* Forward declaration for type */
struct mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi;
struct mcuxClCipherModes_Context_Aes_Sgi;

/** Non-blocking workarea containing all information/fields that need to be handed over to the interrupt callback
    that is triggered once AUTO mode is done.
    This information will be part of the workarea in the session, which is available during interrupt handlers. */
typedef struct mcuxClCipherModes_nonBlockingWa
{
  const struct mcuxClCipherModes_AlgorithmDescriptor_Aes_Sgi * pAlgo; /* Algorithm descriptor as provided by the user */
  struct mcuxClCipherModes_Context_Aes_Sgi * pContext;                /* Context needed to wrap-up multipart flows */
  uint8_t direction;                /* Indicates encryption or decryption for oneshot operations */
  uint32_t lastBlockRemainingBytes; /* Number of bytes in the last block [1..16] for multipart operations */
  uint32_t totalInputLength;        /* Total number of input in bytes */
  uint32_t *pOutputLength;          /* Pointer to outputLength counter */
  mcuxCl_InputBuffer_t pIn;          /* User input buffer */
  uint32_t inOffset;                /* Offset of input buffer */
  mcuxCl_Buffer_t pOut;              /* User output buffer */
  uint32_t outOffset;               /* Offset of output buffer */
} mcuxClCipherModes_nonBlockingWa_t;


typedef struct mcuxClCipherModes_WorkArea
{
  mcuxClAes_Workarea_Sgi_t sgiWa;
  uint32_t *pIV;
  uint32_t ctrSize;
  mcuxClCipherModes_nonBlockingWa_t nonBlockingWa;
} mcuxClCipherModes_WorkArea_t;


#endif /* MCUXCLCIPHERMODES_COMMON_WA_H_ */
