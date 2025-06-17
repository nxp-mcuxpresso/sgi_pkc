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

#ifndef MCUXCLAES_WA_H_
#define MCUXCLAES_WA_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>

#include <mcuxClAes_Constants.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <mcuxClBuffer.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClSgi_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t mcuxClAes_SecureParamWorkArea_t;

typedef struct mcuxClAes_Workarea_Sgi
{
  uint32_t sgiCtrlKey;                              /* SGI configuration (depending on key type) */
  mcuxClSgi_copyOut_t copyOutFunction;               /* Function pointer to copy out data from SGI */
  uint32_t protectionToken_copyOutFunction;
  uint8_t paddingBuff[MCUXCLAES_BLOCK_SIZE];         /* Buffer for padding */
  mcuxClKey_KeyChecksum_t* pKeyChecksums;            /* key checksum pointer to do key checksum verify */
} mcuxClAes_Workarea_Sgi_t;




#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAES_WA_H_ */
