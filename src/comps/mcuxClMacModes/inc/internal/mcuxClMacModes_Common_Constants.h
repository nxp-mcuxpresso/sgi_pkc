/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

#ifndef MCUXCLMACMODES_COMMON_CONSTANTS_H_
#define MCUXCLMACMODES_COMMON_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClMac_Constants.h>
#include <mcuxClAes_Constants.h>

#include <internal/mcuxClCipherModes_Common_Constants.h>

#define MCUXCLMACMODES_SUBKEY_WORD_SIZE            (4U)

/* Mask used to change STATUS OK/COMPARE_NOK into JOB_COMPLETED/JOB_COMPLETED_COMPARE_NOK*/
#define MCUXCLMAC_INTERNAL_STATUS_JOB_COMPLETED_MASK (0x000000FFU)

#define MCUXCLMACMODES_TRUE               (0xA5A5A5A5U)
#define MCUXCLMACMODES_FALSE              (0x5A5A5A5AU)

/* Sizes used in workarea and context */
#define MCUXCLMACMODES_BLOCKSIZE      MCUXCLCIPHERMODES_BLOCKSIZE


#endif /* MCUXCLMACMODES_COMMON_CONSTANTS_H_ */
