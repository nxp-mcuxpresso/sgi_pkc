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

#ifndef MCUXCLCIPHERMODES_COMMON_CONSTANTS_H_
#define MCUXCLCIPHERMODES_COMMON_CONSTANTS_H_

#include <internal/mcuxClAes_Internal_Constants.h>

#define MCUXCLCIPHERMODES_ENCRYPT                     (0U)
#define MCUXCLCIPHERMODES_DECRYPT                     (1U)

#define MCUXCLCIPHERMODES_PADDING_ADDED         (0x001234U)
#define MCUXCLCIPHERMODES_PADDING_NOT_NEEDED    (0x004321U)

#if defined(MCUXCL_FEATURE_CIPHERMODES_DMA_NONBLOCKING)
#define MCUXCLCIPHERMODES_NO_DMA           (0U)
#define MCUXCLCIPHERMODES_USE_DMA          (1U)
#endif /* defined(MCUXCL_FEATURE_SESSION_JOBS) && defined(MCUXCL_FEATURE_CIPHERMODES_DMA_NONBLOCKING) */

#define MCUXCLCIPHERMODES_BLOCKSIZE      (1U)

#endif /* MCUXCLCIPHERMODES_COMMON_CONSTANTS_H_ */
