/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

/** @file  mcuxClHmac_Helper.c
 *  @brief Helper functions of mcuxClHmac
 */

#include <mcuxClToolchain.h>
#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClMac.h>
#include <mcuxClMemory.h>
#include <mcuxClKey.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <mcuxClHmac_Functions.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClHmac_Internal_Functions.h>
#include <internal/mcuxClHmac_Internal_Types.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHmac_createHmacMode)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClHmac_createHmacMode(
    mcuxClMac_CustomMode_t mode,
    mcuxClHash_Algo_t hashAlgorithm)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHmac_createHmacMode);

    /* Balance DI for call to mcuxClMemory_copy_int */
    MCUX_CSSL_DI_RECORD(memCopyDst, (uint32_t) &mode->common);
    MCUX_CSSL_DI_RECORD(memCopySrc, (uint32_t) &mcuxClHmac_CommonModeDescriptor_Sw);
    MCUX_CSSL_DI_RECORD(memCopyLen, (uint32_t) sizeof(mcuxClHmac_CommonModeDescriptor_Sw));
    /* copy the common HMAC mode descriptor into the mode */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int((uint8_t *) &mode->common,
                                                        (uint8_t const *) &mcuxClHmac_CommonModeDescriptor_Sw,
                                                        sizeof(mcuxClHmac_CommonModeDescriptor_Sw)));

    /* Insert hashSize from the hashAlgorithm into the macByteSize field */
    mode->common.macByteSize = hashAlgorithm->hashSize;

    /* pCustom points to the end of the mode descriptor in memory,
       assumes user allocated sufficient memory with MCUXCLMAC_HMAC_MODE_DESCRIPTOR_SIZE */
    uintptr_t pCustomLocation = (uintptr_t)mode + sizeof(mcuxClMac_ModeDescriptor_t);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("integer cast to pointer void *")
    mode->pCustom = (void *) pCustomLocation;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()

    mcuxClHmac_ModeDescriptor_t * hmacModeDescriptor = (mcuxClHmac_ModeDescriptor_t *) mode->pCustom;
    hmacModeDescriptor->hashAlgorithm = (const mcuxClHash_AlgorithmDescriptor_t *) hashAlgorithm;

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHmac_createHmacMode, MCUXCLMAC_STATUS_OK);
}
