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

/** @file  mcuxClAeadModes_Sgi_Ctx.h
 *  @brief Internal structure of the context for the mcuxClAeadModes component
 */

#ifndef MCUXCLAEADMODES_SGI_CTX_H_
#define MCUXCLAEADMODES_SGI_CTX_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <internal/mcuxClAead_Ctx.h>
#include <mcuxClAes.h>
#include <internal/mcuxClAes_Internal_Constants.h>
#include <internal/mcuxClAeadModes_Common_Constants.h>
#include <internal/mcuxClAeadModes_Sgi_Types.h>
#include <internal/mcuxClAes_Ctx.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>

struct mcuxClAeadModes_Context
{
  mcuxClAead_Context_t common;

  mcuxClCipherModes_Context_Aes_Sgi_t cipherCtx;
  mcuxClMacModes_Context_t macCtx;

  uint32_t encDecMode;
  uint8_t  counter0[MCUXCLAES_BLOCK_SIZE];
  uint32_t inSize;     /* input bytes left */
  uint32_t adataSize;  /* size of all adata */
  uint32_t adataCumulativeSize;
  uint32_t tagSize;
  mcuxClAeadModes_alg_process_t process;
  uint32_t protectionToken_process;

};

#endif /* MCUXCLAEADMODES_SGI_CTX_H_ */
