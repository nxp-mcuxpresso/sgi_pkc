/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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

#include <mcuxCsslAnalysis.h>
#include <mcuxClCore_Platform.h>
#include <mcuxClXof_Types.h>
#include <internal/mcuxClXof_Internal.h>
#include <internal/mcuxClHashModes_Internal_Memory.h>
#include <internal/mcuxClXofModes_Internal_Memory.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClXof_WaCpuMax          [MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE];
volatile uint8_t mcuxClXof_compute_WaCpuMax  [MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE];
volatile uint8_t mcuxClXof_init_WaCpuMax     [MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE];
volatile uint8_t mcuxClXof_process_WaCpuMax  [MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE];
volatile uint8_t mcuxClXof_generate_WaCpuMax [MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE];
volatile uint8_t mcuxClXof_finish_WaCpuMax   [MCUXCLXOF_INTERNAL_WACPU_SIZE_SHAKE];

/* Xof multipart context size generation */
volatile uint8_t mcuxClXof_Ctx_size_max      [MCUXCLXOFMODES_CONTEXT_MAX_SIZE_INTERNAL];
volatile uint8_t mcuxClXof_Shake128_Ctx_size [MCUXCLXOFMODES_SHAKE128_CONTEXT_SIZE_INTERNAL];
volatile uint8_t mcuxClXof_Shake256_Ctx_size [MCUXCLXOFMODES_SHAKE256_CONTEXT_SIZE_INTERNAL];
volatile uint8_t mcuxClXof_SecShake128_Ctx_size [MCUXCLXOFMODES_SECSHAKE128_CONTEXT_SIZE_INTERNAL];
volatile uint8_t mcuxClXof_SecShake256_Ctx_size [MCUXCLXOFMODES_SECSHAKE256_CONTEXT_SIZE_INTERNAL];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
