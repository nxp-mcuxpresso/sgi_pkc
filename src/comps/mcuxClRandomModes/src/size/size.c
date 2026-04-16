/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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

/**
 *
 * @file:	size.c
 * @brief:	This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClRandomModes_Internal_SizeDefinitions.h>

#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <mcuxClRandom_Types.h>
#include <internal/mcuxClRandom_Internal_Types.h>

/* *********************** */
/* *** Work area sizes *** */
/* *********************** */
MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClRandom_Mode_Descriptor_size[sizeof(mcuxClRandom_ModeDescriptor_t)];

#ifdef MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_128
volatile mcuxClRandomModes_Context_CtrDrbg_Aes128_t mcuxClRandomModes_Context_Aes128;
#endif

#ifdef MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_192
volatile mcuxClRandomModes_Context_CtrDrbg_Aes192_t mcuxClRandomModes_Context_Aes192;
#endif

#ifdef MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_256
volatile mcuxClRandomModes_Context_CtrDrbg_Aes256_t mcuxClRandomModes_Context_Aes256;
#endif

volatile mcuxClRandom_Context_t mcuxClRandomModes_Context_PatchMode;

volatile uint8_t mcuxClRandomModes_CpuWA_MaxSize[MCUXCLRANDOMMODES_CPUWA_MAXSIZE];
volatile uint8_t mcuxClRandomModes_init_CpuWA_Size[MCUXCLRANDOMMODES_INIT_WACPU_SIZE_MAX];
volatile uint8_t mcuxClRandomModes_reseed_CpuWA_Size[MCUXCLRANDOMMODES_RESEED_WACPU_SIZE_MAX];
volatile uint8_t mcuxClRandomModes_generate_CpuWA_Size[MCUXCLRANDOMMODES_GENERATE_WACPU_SIZE_MAX];
volatile uint8_t mcuxClRandomModes_selftest_CpuWA_Size[MCUXCLRANDOMMODES_SELFTEST_WACPU_SIZE_MAX];

/* *********************** */
/* *** Entropy sizes   *** */
/* *********************** */
#ifdef MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_128
volatile uint8_t mcuxClRandomModes_TestMode_CtrDrbg_Aes128_Entropy_Input_Init_size[MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES128];
volatile uint8_t mcuxClRandomModes_TestMode_CtrDrbg_Aes128_Entropy_Input_Reseed_size[MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES128];
#endif

#ifdef MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_192
volatile uint8_t mcuxClRandomModes_TestMode_CtrDrbg_Aes192_Entropy_Input_Init_size[MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES192];
volatile uint8_t mcuxClRandomModes_TestMode_CtrDrbg_Aes192_Entropy_Input_Reseed_size[MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES192];
#endif

#ifdef MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_256
volatile uint8_t mcuxClRandomModes_TestMode_CtrDrbg_Aes256_Entropy_Input_Init_size[MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256];
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
volatile uint8_t mcuxClRandomModes_TestMode_CtrDrbg_Aes256_Entropy_Input_Reseed_size[MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES256];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
#endif

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
