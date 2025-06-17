/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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

/** @file  mcuxClMacModes_Common.c
 *  @brief Implementation of mcuxClMacModes component public API
 */

#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClMacModes_Constants.h>
#include <mcuxClMacModes_Functions.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCipher_Constants.h>

#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClMacModes_Common_Constants.h>
#include <internal/mcuxClMacModes_Common_Types.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClMacModes_Sgi_Algorithms.h>
#include <internal/mcuxClMacModes_Sgi_Gmac.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_createGmacMode)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_createGmacMode(
  mcuxClMac_CustomMode_t mode,
  mcuxCl_InputBuffer_t pIv,
  uint32_t ivLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_createGmacMode);

  /* copy the common GMAC mode descriptor into the mode */
  MCUX_CSSL_DI_RECORD(mode_cpy, (uint32_t)&mode->common);
  MCUX_CSSL_DI_RECORD(mode_cpy, (uint32_t)&mcuxClMac_CommonModeDescriptor_GMAC);
  MCUX_CSSL_DI_RECORD(mode_cpy, sizeof(mcuxClMac_CommonModeDescriptor_GMAC));

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_int(
    (uint8_t *)&mode->common,
    (const uint8_t *)&mcuxClMac_CommonModeDescriptor_GMAC,
    sizeof(mcuxClMac_CommonModeDescriptor_GMAC)));

  /* pCustom points to the end of the mode descriptor in memory,
     assumes user allocated sufficient memory with MCUXCLMAC_GMAC_MODE_DESCRIPTOR_SIZE */
  uintptr_t pCustomLocation = (uintptr_t)mode + sizeof(mcuxClMac_ModeDescriptor_t);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER("integer cast to pointer void *")
  mode->pCustom = (void *) pCustomLocation;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_TYPECAST_BETWEEN_INTEGER_AND_POINTER()

  mcuxClMacModes_GmacModeDescriptor_t * gmacModeDescriptor = (mcuxClMacModes_GmacModeDescriptor_t *) mode->pCustom;
  gmacModeDescriptor->pIv = pIv;
  gmacModeDescriptor->ivLength = ivLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMacModes_createGmacMode, MCUXCLMAC_STATUS_OK, MCUXCLMAC_STATUS_FAULT_ATTACK);
}

