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

#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Platform.h>

#include <mcuxClCrc.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClCrc_Internal_Constants.h>
#include <internal/mcuxClCrc_Internal_Functions.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_computeCRC16)
MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClCrc_computeCRC16(const uint8_t *pBytes, uint32_t length)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_computeCRC16);
  MCUX_CSSL_DI_RECORD(mcuxClCrc_Internal_updateCRC16_pBytes, (uint32_t)pBytes + length);

  MCUX_CSSL_FP_FUNCTION_CALL(uint16_t, crcRet, mcuxClCrc_Internal_updateCRC16(pBytes, length, MCUXCLCRC_DEFAULT_SEED_16));
  const uint16_t crcResult = crcRet ^ MCUXCLCRC_DEFAULT_CRC_OUT_MASK_16;
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCrc_computeCRC16, crcResult,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Internal_updateCRC16));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_computeCRC32)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClCrc_computeCRC32(const uint8_t *pBytes, uint32_t length)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_computeCRC32);
  MCUX_CSSL_DI_RECORD(mcuxClCrc_Internal_updateCRC32_pBytes, (uint32_t)pBytes + length);

  MCUX_CSSL_FP_FUNCTION_CALL(crcRet, mcuxClCrc_Internal_updateCRC32(pBytes, length, MCUXCLCRC_DEFAULT_SEED_32));
  const uint32_t crcResult = crcRet ^ MCUXCLCRC_DEFAULT_CRC_OUT_MASK_32;
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCrc_computeCRC32, crcResult,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Internal_updateCRC32));
}
