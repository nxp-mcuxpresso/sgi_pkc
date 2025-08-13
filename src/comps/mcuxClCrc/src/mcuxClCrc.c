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

#include <internal/mcuxClCrc_Drv.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_computeCRC16)
MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClCrc_computeCRC16(const uint8_t *pBytes, uint32_t length)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_computeCRC16);
  MCUX_CSSL_DI_RECORD(mcuxClCrc_Internal_updateCRC16_pBytes, (uint32_t)pBytes + length);

  /* Configure CRC to perform 16-bit CRC computation with a given seed
   * and the platform-specified 16-bit CRC polynomial.
   * Also configure the writes to be byte-wise transposed */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_Drv_configureCRC16(
    MCUXCLCRC_DEFAULT_POLY_16,
    MCUXCLCRC_DEFAULT_SEED_16,
    MCUXCLCRC_DRV_WRITE_TRANSPOSE_BYTES_NO_BITS));

  MCUX_CSSL_FP_FUNCTION_CALL(uint16_t, crcRet, mcuxClCrc_Drv_updateCRC16(pBytes, length));
  const uint16_t crcResult = crcRet ^ MCUXCLCRC_DEFAULT_CRC_OUT_MASK_16;
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCrc_computeCRC16, crcResult,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Drv_configureCRC16),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Drv_updateCRC16));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_computeCRC32)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClCrc_computeCRC32(const uint8_t *pBytes, uint32_t length)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_computeCRC32);
  MCUX_CSSL_DI_RECORD(mcuxClCrc_Internal_updateCRC32_pBytes, (uint32_t)pBytes + length);

  /* Configure CRC to perform 32-bit CRC computation with a given seed
   * and the platform-specified 32-bit CRC polynomial.
   * Also configure both reads and writes to be byte-wise transposed */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_Drv_configureCRC32(
    MCUXCLCRC_DEFAULT_POLY_32,
    MCUXCLCRC_DEFAULT_SEED_32,
    MCUXCLCRC_DRV_READ_TRANSPOSE_BYTES_NO_BITS | MCUXCLCRC_DRV_WRITE_TRANSPOSE_BYTES_NO_BITS));

  MCUX_CSSL_FP_FUNCTION_CALL(crcRet, mcuxClCrc_Drv_updateCRC32(pBytes, length));
  const uint32_t crcResult = crcRet ^ MCUXCLCRC_DEFAULT_CRC_OUT_MASK_32;
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCrc_computeCRC32, crcResult,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Drv_configureCRC32),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Drv_updateCRC32));
}
