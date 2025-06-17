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

#ifndef MCUXCLMACMODES_COMMON_WA_H_
#define MCUXCLMACMODES_COMMON_WA_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Macros.h>
#include <mcuxClMac_Types.h>
#include <internal/mcuxClMacModes_Common_Constants.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>
#include <internal/mcuxClCipherModes_Common_Wa.h>
#include <mcuxClAes.h>
#include <internal/mcuxClAes_Wa.h>
#include <internal/mcuxClAes_Ctx.h>
#include <internal/mcuxClAes_Internal_Constants.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Non-blocking workarea containing all information/fields that need to be handed over to the interrupt callback
    that is triggered once AUTO mode is done.
    This information will be part of the workarea in the session, which is available during interrupt handlers. */
typedef struct mcuxClMacModes_nonBlockingWa
{
  const mcuxClMac_ModeDescriptor_t * pMode;                /* Mode descriptor as provided by the user */
  mcuxClMacModes_Context_t * pContext;                     /* Context needed to wrap-up multipart flows */
  uint32_t inLength;                                      /* inLength as provided by the user */
  mcuxCl_InputBuffer_t pIn;                                /* Pointer to input data*/
  uint32_t inputOffset;                                   /* Offset for input data*/
  uint32_t processedBytes;                                /* Currently processed bytes*/
  union
  {
    mcuxCl_Buffer_t output;                                /* Pointer to buffer for compute MAC*/
    mcuxCl_InputBuffer_t input;                            /* Pointer to input buffer for compare MAC*/
  } pMac;

  uint32_t macLength;                                    /* Length of the mac */
  uint32_t *pOutputLength;                               /* Pointer to outputLength counter */

} mcuxClMacModes_nonBlockingWa_t;

typedef struct mcuxClMacModes_WorkArea
{
  mcuxClAes_Workarea_Sgi_t sgiWa;                           /* SGI configuration (depending on key type) */
  mcuxClMacModes_nonBlockingWa_t nonBlockingWa;
  union
  {
    uint32_t subKeys[2][MCUXCLMACMODES_SUBKEY_WORD_SIZE];   /* Buffer to store generated subkeys */

    struct
    {
      uint32_t counter0[MCUXCLAES_BLOCK_SIZE_IN_WORDS];     /* Buffer for the first counter for GMAC, J0 */
      uint32_t maskedPreTag[MCUXCLAES_BLOCK_SIZE_IN_WORDS]; /* Buffer for the masked preTag */
    } gmac;

  } algoWa;
} mcuxClMacModes_WorkArea_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMACMODES_COMMON_WA_H_ */
