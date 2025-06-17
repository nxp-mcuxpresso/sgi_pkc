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

#ifndef MCUXCLCIPHERMODES_COMMON_CONSTANTS_H_
#define MCUXCLCIPHERMODES_COMMON_CONSTANTS_H_

#include <internal/mcuxClAes_Internal_Constants.h>

#define MCUXCLCIPHERMODES_ENCRYPT                     (0u)
#define MCUXCLCIPHERMODES_DECRYPT                     (1u)

#define MCUXCLCIPHERMODES_PADDING_ADDED         (0x001234u)
#define MCUXCLCIPHERMODES_PADDING_NOT_NEEDED    (0x004321u)

#define MCUXCLCIPHERMODES_NO_DMA           (0u)
#define MCUXCLCIPHERMODES_USE_DMA          (1u)

/* Sizes used in workarea and context */
#define MCUXCLCIPHERMODES_ROUNDKEYSSIZE  (1u)
#define MCUXCLCIPHERMODES_BLOCKSIZE      (1u)


#endif /* MCUXCLCIPHERMODES_COMMON_CONSTANTS_H_ */
