/*--------------------------------------------------------------------------*/
/* Copyright 2022-2026 NXP                                                  */
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
/* Internal constants for subkeys             */
/**********************************************/
#define MCUXCLAES_GCM_H_KEY_SIZE                (16u)
#define MCUXCLAES_GCM_H_KEY_SIZE_IN_WORDS       (MCUXCLAES_GCM_H_KEY_SIZE / sizeof(uint32_t))
#define MCUXCLAES_MAC_SUB_KEY_SIZE              (16u)


/**********************************************/
/* Internal constants for key encodings       */
/**********************************************/
#define MCUXCLAES_KEYCHECKSUM_CRC_REFERENCE_INDEX   (0) //reference CRC index in mcuxClKey_KeyChecksum.data
#define MCUXCLAES_KEYCHECKSUM_CRC_SFRMASK_INDEX     (1) //sfrseed index in mcuxClKey_KeyChecksum.data


/* default 32-bit SGI SFR mask constant */
#define MCUXCLAES_KEY_CHECKSUM_SFRMASKING_SEED             (0xF0F0F0F0u)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAES_INTERNAL_CONSTANTS_H_ */
