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

/**
 * @file:  size.c
 * @brief: This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxCsslAnalysis.h>
#include <mcuxClCore_Macros.h>
#include <internal/mcuxClAes_Wa.h>
#include <internal/mcuxClCipherModes_Common_Wa.h>

/* *********************** */
/* *** Work area sizes *** */
/* *********************** */

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()

#include <internal/mcuxClCipherModes_Sgi_Types.h>
volatile uint8_t mcuxClCipherModes_WorkArea_Aes_Sgi[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClCipherModes_WorkArea_t))];

volatile mcuxClCipherModes_Context_Aes_Sgi_t mcuxClCipherModes_Context_Aes_SGI;


MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
