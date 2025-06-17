/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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

#ifndef MCUXCLAES_INTERNAL_CONSTANTS_H_
#define MCUXCLAES_INTERNAL_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClAes_Constants.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************/
/* Internal constants for keys in the context */
/**********************************************/
#define MCUXCLAES_MASKED_KEY_SIZE               (32u)  ///> Maximal size of a masked key in the context in bytes
#define MCUXCLAES_MASKED_KEY_SIZE_IN_WORDS      (MCUXCLAES_MASKED_KEY_SIZE / sizeof(uint32_t)) ///> Maximal size of a masked key in the context in words

// TODO CLNS-17176: Remove these two constants again
#define MCUXCLAES_KEYCONTEXT_KEYDATA_MASKED_IN_CONTEXT (0xc2c2c2c2U) ///< The key is stored SFR-masked in the context. Used as a flag in the mcuxClAes_KeyContext_Sgi_t type.
#define MCUXCLAES_KEYCONTEXT_KEYHANDLE_IN_CONTEXT      (0x2c2c2c2cU) ///< The key is stored as a handle in the context and needs to be loaded. Used as a flag in the mcuxClAes_KeyContext_Sgi_t type.


/**********************************************/
/* Internal constants for subkeys             */
/**********************************************/
#define MCUXCLAES_GCM_H_KEY_SIZE                (16u)
#define MCUXCLAES_MAC_SUB_KEY_SIZE              (16u)


/**********************************************/
/* Internal constants for key encodings       */
/**********************************************/
#define MCUXCLAES_KEYCHECKSUM_CRC_REFERENCE_INDEX   (0) //reference CRC index in mcuxClKey_KeyChecksum.data
#define MCUXCLAES_KEYCHECKSUM_CRC_SFRMASK_INDEX     (1) //sfrseed index in mcuxClKey_KeyChecksum.data


/* default 32-bit SGI SFR mask constant */
#define MCUXCLAES_KEY_CHECKSUM_SFRMASKING_SEED             (0xF0F0F0F0u)


/**********************************************/
/* Internal constants for security options    */
/**********************************************/


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAES_INTERNAL_CONSTANTS_H_ */
