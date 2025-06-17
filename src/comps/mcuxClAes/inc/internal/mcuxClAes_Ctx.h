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

#ifndef MCUXCLAES_CTX_H_
#define MCUXCLAES_CTX_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClAes_Internal_Constants.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct mcuxClAes_KeyContext_Sgi
{
  mcuxClKey_Descriptor_t* key;    /* Key handle of the external key. Ignored if keyLocationInfo=MCUXCLAES_KEYCONTEXT_KEYDATA_MASKED_IN_CONTEXT. */
  uint32_t slot;                 /* Contains the slot the internal key is loaded to. Ignored if keyLocationInfo=MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT. */
  uint32_t keyLocationInfo;      /* Information how the key is stored in the context.
                                  * If MCUXCLAES_KEYCONTEXT_KEYDATA_MASKED_IN_CONTEXT: The key is stored masked in the context, and copied to SGI for each operation.
                                  * If MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT: The key needs to be loaded (if not preloaded) from the handle for each operation. */
  mcuxClKey_Size_t keySize;                                /* Key size (depending on key type) */
  uint32_t keySeed;                                       /* Key seed of SFR-masked key */
  uint32_t keyMasked[MCUXCLAES_MASKED_KEY_SIZE_IN_WORDS];  /* Buffer to store the key in SFR-masked format */
  uint32_t sgiCtrlKey;                                    /* SGI configuration (depending on key type) */
  mcuxClKey_KeyChecksum_t  keyChecksums;                   /* Buffer to store the key checksum info */
} mcuxClAes_KeyContext_Sgi_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAES_CTX_H_ */
