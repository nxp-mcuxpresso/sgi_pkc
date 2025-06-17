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

/**
 *
 * @file:	size.c
 * @brief:	This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClAeadModes_Common.h>

/* *********************************************************** */
/* Work area and ctx sizes.                                    */
/* All work area size shall be a multiple of CPU wordsize.     */
/* *********************************************************** */

#include <internal/mcuxClAeadModes_Common_Wa.h>
#include <internal/mcuxClAeadModes_Sgi_Ctx.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClAeadModes_WorkArea_size[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(
    MCUXCLCORE_MAX(MCUXCLCORE_MAX(sizeof(mcuxClAeadModes_WorkArea_t), sizeof(mcuxClMacModes_WorkArea_t)),
                  sizeof(mcuxClCipherModes_WorkArea_t)))];
volatile uint8_t mcuxClAead_OneShot[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClAeadModes_WorkArea_t))
                                   + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClAeadModes_Context_t))];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()


MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile struct mcuxClAeadModes_Context mcuxClAeadModes_Context_size;
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
