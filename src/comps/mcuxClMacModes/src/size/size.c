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
 *
 * @file: size.c
 * @brief: This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClCore_Macros.h>
#include <internal/mcuxClMacModes_Common_Types.h>
#include <internal/mcuxClMacModes_Common_Memory.h>
#include <internal/mcuxClMacModes_Common_Wa.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>

/*************************/
/**** Work area sizes ****/
/*************************/

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()


#define MCUXCLMACMODES_SW_PRIMITIVE_WA_SIZE (0u)


/* Context and WA for MAC computation */
volatile mcuxClMacModes_Context_t mcuxClMacModes_Ctx;
volatile uint8_t mcuxClMacModes_WA[MCUXCLMACMODES_INTERNAL_WASIZE + MCUXCLMACMODES_SW_PRIMITIVE_WA_SIZE];

/* Mode-specific structures */
volatile uint8_t mcuxClMacModes_GmacModeDescriptor_SIZE[sizeof(mcuxClMac_ModeDescriptor_t) + sizeof(mcuxClMacModes_GmacModeDescriptor_t)];

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
