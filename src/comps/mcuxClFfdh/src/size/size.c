/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClRandomModes_Internal_SizeDefinitions.h>

#include <mcuxClFfdh_Types.h>
#include <internal/mcuxClPkc_Internal_Types.h>
#include <internal/mcuxClFfdh_Internal.h>
#include <internal/mcuxClFfdh_Internal_PkcDefs.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()

volatile uint8_t mcuxClKey_Agreement_FFDH_WaCPU_Size_2048[SIZEOF_FFDHCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (FFDH_UPTRT_COUNT)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClKey_Agreement_FFDH_WaCPU_Size_3072[SIZEOF_FFDHCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (FFDH_UPTRT_COUNT)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClKey_Agreement_FFDH_WaCPU_Size_4096[SIZEOF_FFDHCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (FFDH_UPTRT_COUNT)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClKey_Agreement_FFDH_WaCPU_Size_6144[SIZEOF_FFDHCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (FFDH_UPTRT_COUNT)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];

#define FDDH_TEMP_BUFFER_SIZE8192 MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(8192U / 8U + 1U)
volatile uint8_t mcuxClKey_Agreement_FFDH_WaCPU_Size_8192[SIZEOF_FFDHCPUWA_T + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(uint16_t) * (FFDH_UPTRT_COUNT)) + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE) + FDDH_TEMP_BUFFER_SIZE8192];

volatile uint8_t mcuxClFfdh_PKC_wordsize[MCUXCLPKC_WORDSIZE];

volatile uint8_t mcuxClFfdh_KeyAgreement_WaPKC_NoOfBuffers[FFDH_NO_OF_BUFFERS];

/* Sizes of buffers in PKC RAM are extended by 1FW due to MCUXCLMATH_SECMODEXP requirements.
   For large field elements certain optimizations are in place:
   - last buffer in PKC memory is smaller with size equal to 6 * MCUXCLPKC_WORDSIZE due to MCUXCLMATH_SECMODEXP properties.
   - one of the buffers for MCUXCLMATH_SECMODEXP shall be placed in CPU RAM. */
volatile uint8_t mcuxClKey_Agreement_FFDH_WaPKC_Size_2048 [FFDH_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(2048U / 8U + 1U) + MCUXCLPKC_WORDSIZE)];

volatile uint8_t mcuxClKey_Agreement_FFDH_WaPKC_Size_3072 [FFDH_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(3072U / 8U + 1U) + MCUXCLPKC_WORDSIZE)];

volatile uint8_t mcuxClKey_Agreement_FFDH_WaPKC_Size_4096 [FFDH_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(4096U / 8U + 1U) + MCUXCLPKC_WORDSIZE)];

volatile uint8_t mcuxClKey_Agreement_FFDH_WaPKC_Size_6144 [FFDH_NO_OF_BUFFERS * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(6144U / 8U + 1U) + MCUXCLPKC_WORDSIZE)];

/* Formulas reflect aformentioned optimizations */
volatile uint8_t mcuxClKey_Agreement_FFDH_WaPKC_Size_8192 [(FFDH_NO_OF_BUFFERS - 2U) * (MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(8192U / 8U + 1U) + MCUXCLPKC_WORDSIZE) + 6U * MCUXCLPKC_WORDSIZE];


MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
