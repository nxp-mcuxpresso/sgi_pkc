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

#include <mcuxClCore_Platform.h>
#include <mcuxClCrc.h>
#include <internal/mcuxClCrc_Internal_Functions.h>
#include <internal/mcuxClCrc_Internal_Constants.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClCore_FunctionIdentifiers.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_Internal_updateCRC16)
MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClCrc_Internal_updateCRC16(const uint8_t *pBytes, uint32_t length, uint16_t seed16)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_Internal_updateCRC16);
    uint16_t crc = seed16;

    MCUX_CSSL_FP_LOOP_DECL(outerLoop);
    for (uint32_t byteIndex = 0U; byteIndex < length; byteIndex++)
    {
        crc ^= ((uint16_t) pBytes[byteIndex] << 8u);
        for (uint32_t bitIndex = 0u; bitIndex < 8u; bitIndex++)
        {
            if (0u != (crc & 0x8000u))
            {
                crc = (uint16_t) ((((uint32_t) crc << 1u) ^ MCUXCLCRC_DEFAULT_POLY_16) & (uint32_t) 0xFFFFu);
            }
            else
            {
                crc <<= 1u;
            }
        }
        /* No FA protection needed. Minimal protection over the data length is sufficient. */
        MCUX_CSSL_FP_LOOP_ITERATION(outerLoop);
    }

    /* Do FA protection, only for compatibility with HW-based implementation */
    MCUX_CSSL_DI_EXPUNGE(identifier, (uint32_t)pBytes + length);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCrc_Internal_updateCRC16, crc,
        MCUX_CSSL_FP_LOOP_ITERATIONS(outerLoop, length));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_Internal_updateCRC16_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(uint16_t) mcuxClCrc_Internal_updateCRC16_buffer(mcuxCl_InputBuffer_t bufSrc, uint32_t length, uint16_t seed16)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_Internal_updateCRC16_buffer);

  MCUX_CSSL_FP_FUNCTION_CALL(uint16_t, crcRet, mcuxClCrc_Internal_updateCRC16(bufSrc, length, seed16));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCrc_Internal_updateCRC16_buffer, crcRet,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Internal_updateCRC16));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_Internal_updateCRC32)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClCrc_Internal_updateCRC32(const uint8_t *pBytes, uint32_t length, uint32_t seed32)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_Internal_updateCRC32);

    uint32_t crc = seed32;

    MCUX_CSSL_FP_LOOP_DECL(outerLoop);
    for (uint32_t byteIndex = 0u; byteIndex < length; byteIndex++)
    {
        crc ^= ((uint32_t) pBytes[byteIndex] << 24u);
        for (uint32_t bitIndex = 0u; bitIndex < 8u; bitIndex++)
        {
            if (0u != (crc & 0x80000000u))
            {
                crc = (crc << 1u) ^ MCUXCLCRC_DEFAULT_POLY_32;
            }
            else
            {
                crc <<= 1u;
            }
        }
        /* No FA protection needed. Minimal protection of the data length is sufficient. */
        MCUX_CSSL_FP_LOOP_ITERATION(outerLoop);
    }

    /* byte reverse */
    uint32_t swap = ((crc << 24) & 0xFF000000u)
                  | ((crc << 8)  & 0x00FF0000u)
                  | ((crc >> 8)  & 0x0000FF00u)
                  | ((crc >> 24) & 0x000000FFu);

    /* Do FA protection, only for compatibility with HW-based implementation */
    MCUX_CSSL_DI_EXPUNGE(identifier, (uint32_t)pBytes + length);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCrc_Internal_updateCRC32, swap,
        MCUX_CSSL_FP_LOOP_ITERATIONS(outerLoop, length));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_Internal_updateCRC32_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClCrc_Internal_updateCRC32_buffer(mcuxCl_InputBuffer_t bufSrc, uint32_t length, uint32_t seed32)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_Internal_updateCRC32_buffer);

  MCUX_CSSL_FP_FUNCTION_CALL(crcRet, mcuxClCrc_Internal_updateCRC32(bufSrc, length, seed32));

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCrc_Internal_updateCRC32_buffer, crcRet,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Internal_updateCRC32));
}

