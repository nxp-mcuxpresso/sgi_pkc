/*--------------------------------------------------------------------------*/
/* Copyright 2021-2024 NXP                                                  */
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

/** @file  mcuxClAeadModes_Common_Constants.h
 *  @brief Internal definitions for the mcuxClAeadModes component */


#ifndef MCUXCLAEADMODES_COMMON_CONSTANTS_H_
#define MCUXCLAEADMODES_COMMON_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClMemory_Constants.h>

#include <internal/mcuxClMacModes_Common_Constants.h>


#define MCUXCLAEADMODES_ENCRYPTION (1u)
#define MCUXCLAEADMODES_DECRYPTION (2u)

#define MCUXCLAEADMODES_CCM (0x55555555u)
#define MCUXCLAEADMODES_GCM (0xAAAAAAAAu)

/* GCM uses a 32-bit big-endian counter */
#define MCUXCLAEADMODES_GCM_CTR_SIZE             (sizeof(uint32_t))
#define MCUXCLAEADMODES_GCM_CTR_SIZE_IN_WORDS    (MCUXCLAEADMODES_GCM_CTR_SIZE / sizeof(uint32_t))

/* Buffer B0 contains the first block B0, l(a), and the first AAD bytes */
#define MCUXCLAEADMODES_CCM_B0_SIZE     (16u)

/* The maximum lengths for tag and nonce are given by the limitations from CCM:
 * The only possible lengths are:
 *    nonce: 7,8,9,10,11,12,13
 *    tag: 4,6,8,10,12,14,16
 */
#define MCUXCLAEADMODES_TAGLEN_MAX           (16u)
#define MCUXCLAEADMODES_NONCELEN_MAX         (13u)

/* For DI protection of the comparison status and the AEAD return code */
#define MCUXCLAEADMODES_INTERNAL_COMP_OK     \
            (MCUXCLAEAD_STATUS_OK + MCUXCLMEMORY_STATUS_EQUAL)
#define MCUXCLAEADMODES_INTERNAL_COMP_NOT_OK \
            (MCUXCLAEAD_STATUS_INVALID_TAG + MCUXCLMEMORY_STATUS_NOT_EQUAL)

/* Size used in workarea and context */
#define MCUXCLAEADMODES_BLOCKSIZE           MCUXCLMACMODES_BLOCKSIZE
#define MCUXCLAEADMODES_BLOCKSIZE_IN_WORDS  MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLAEADMODES_BLOCKSIZE)

#endif /* MCUXCLAEADMODES_COMMON_CONSTANTS_H_ */
