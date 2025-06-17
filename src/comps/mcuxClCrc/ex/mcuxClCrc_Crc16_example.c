/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023 NXP                                                 */
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

/**
 * @example mcuxClCrc_Crc16_example.c
 * @brief Example of using function computeCRC16 to perform a CRC-16 checksum generation
 *        on a given data buffer.
 */

#include <stdint.h>
#include <stddef.h>

#include <mcuxClCrc.h> // Interface to the entire mcuxClCrc component
#include <mcuxClCore_Examples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

/**********************************************************/
/* Example test vectors                                   */
/**********************************************************/

/**
 * @brief Example data buffer.
 */
static const uint8_t data[] = {
    0x2Fu, 0xE4u, 0x26u, 0xB1u, 0x20u, 0x75u, 0x39u, 0x5Eu,
    0x18u, 0x20u, 0xD6u, 0xA5u, 0xBEu, 0xEEu, 0x92u, 0xF2u,
    0xB3u, 0xD7u, 0x9Eu, 0x8Bu, 0x46u
 };


#define NCP_CL_CRC_REF_RESULT 0x6aDBu   // Reference result of CRC-16 operation on given data buffer.


/**
 * @brief Performs a call to function mcuxClCrc_computeCRC16
 *
 * @retval MCUXCLEXAMPLE_STATUS_OK      The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR   The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClCrc_Crc16_example)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCrc_computeCRC16(
                                            data,
                                            sizeof(data))
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeCRC16) != token) || (NCP_CL_CRC_REF_RESULT != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCLEXAMPLE_STATUS_OK;
}
