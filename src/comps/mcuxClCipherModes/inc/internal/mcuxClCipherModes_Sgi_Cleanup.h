/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

#ifndef MCUXCLCIPHERMODES_SGI_CLEANUP_H_
#define MCUXCLCIPHERMODES_SGI_CLEANUP_H_

#include <mcuxClSession_Types.h>
#include <mcuxClSgi_Types.h>

/* Defines to control HW cleanup in cleanupOnExit functions. */
#define MCUXCLCIPHERMODES_CLEANUP_HW_ALL     0x00000F0Fu
#define MCUXCLCIPHERMODES_CLEANUP_HW_SGI     0x0000000Fu
#define MCUXCLCIPHERMODES_CLEANUP_HW_DMA     0x00000F00u
#define MCUXCLCIPHERMODES_CLEANUP_HW_NONE    0xFFFF0000u

#endif /* MCUXCLCIPHERMODES_SGI_CLEANUP_H_ */
