/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
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

#include <mcuxCsslAnalysis.h>
#include <mcuxClCore_Platform.h>

#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHash_Internal_Memory.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()

volatile uint8_t mcuxClHash_WaCpuMax [MCUXCLHASH_INTERNAL_WACPU_MAX];

/* Hash multipart context size generation */

volatile uint8_t mcuxClHash_Ctx_size_max[MCUXCLHASH_CONTEXT_MAX_SIZE_INTERNAL];

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
