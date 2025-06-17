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

#ifndef MCUXCLMACMODES_SGI_CTX_H_
#define MCUXCLMACMODES_SGI_CTX_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClAes.h>

#include <internal/mcuxClAes_Ctx.h>
#include <internal/mcuxClAes_Internal_Constants.h>
#include <internal/mcuxClMac_Ctx.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClMacModes_Common_Constants.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Mac context structure for modes using SGI HW
 *
 * This structure captures all the information that the Mac interface needs to
 * know for a particular Mac mode/algorithm to work.
 */
typedef struct mcuxClMacModes_Context
{
  mcuxClMac_Context_t common;                            /* Common field of the context, for all modes */
  uint32_t blockBuffer[MCUXCLAES_BLOCK_SIZE_IN_WORDS];   /* Buffer of size block-size, to accumulate input data */
  uint32_t blockBufferUsed;                             /* How many bytes in mode-specific blockBuffer are used */
  uint32_t maskedPreTag[MCUXCLAES_BLOCK_SIZE_IN_WORDS];  /* Intermediate result of CMAC operation (masked) */
  mcuxClAes_KeyContext_Sgi_t keyContext;                 /* Common key context; sfr seed will be re-used for preTag masking */
  uint32_t dataProcessed;                               /* Indicate, whether data has been processed */
  uint32_t totalInput;                                  /* Total number of input bytes */
  // TODO CLNS-17176: Use new type mcuxClAes_SubKeyContext_Sgi_t for HKey
  mcuxClAes_KeyContext_Sgi_t HkeyContext;                      /* Common H-key context */
  uint32_t counter0[MCUXCLAES_BLOCK_SIZE_IN_WORDS];            /* Buffer for the first counter for GMAC, J0 */
} mcuxClMacModes_Context_t;


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMACMODES_SGI_CTX_H_ */
