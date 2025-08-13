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

#include <mcuxClToolchain.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClBuffer.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClHashModes_Internal_Resource_Common.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClHashModes_Internal_sgi_sha2_common.h>


/**********************************************************
 * Algorithm descriptor implementations
 **********************************************************/

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha224 =
{
    .sgiUtilsInitHash                 = mcuxClSgi_Utils_initSha224,
    .protectionToken_sgiUtilsInitHash = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_initSha224),
    .sgiLoadInternalDataBlock         = mcuxClSgi_Utils_load512BitBlock,
    .protectionToken_sgiLoadInternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock),
};




const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha256 =
{
    .sgiUtilsInitHash                 = mcuxClSgi_Utils_initSha256,
    .protectionToken_sgiUtilsInitHash = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_initSha256),
    .sgiLoadInternalDataBlock         = mcuxClSgi_Utils_load512BitBlock,
    .protectionToken_sgiLoadInternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock),
};



const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha384 =
{
    .sgiUtilsInitHash                 = mcuxClSgi_Utils_initSha384,
    .protectionToken_sgiUtilsInitHash = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_initSha384),
    .sgiLoadInternalDataBlock         = mcuxClSgi_Utils_load1024BitBlock,
    .protectionToken_sgiLoadInternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load1024BitBlock),
};


const mcuxClHashModes_Internal_AlgorithmDescriptor_t mcuxClHashModes_Internal_AlgorithmDescriptor_Sgi_Sha512 =
{
    .sgiUtilsInitHash                 = mcuxClSgi_Utils_initSha512,
    .protectionToken_sgiUtilsInitHash = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_initSha512),
    .sgiLoadInternalDataBlock         = mcuxClSgi_Utils_load1024BitBlock,
    .protectionToken_sgiLoadInternalDataBlock = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load1024BitBlock),
};




MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
