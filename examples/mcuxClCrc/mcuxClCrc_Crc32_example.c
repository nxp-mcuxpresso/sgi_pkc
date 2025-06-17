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
 * @example mcuxClCrc_Crc32_example.c
 * @brief Example of using function computeCRC32 to perform a CRC-32 checksum generation
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
    0xA1u, 0xEBu, 0xC4u, 0xBFu, 0x58u, 0xE7u, 0xB3u, 0xA3u,
    0xD3u, 0x08u, 0x41u, 0xEDu, 0x0Bu, 0x99u, 0x56u, 0x2Au,
    0xEBu, 0xB8u, 0xDEu, 0x6Du, 0x15u, 0xAEu, 0x26u
 };


#define NCP_CL_CRC_REF_RESULT 0x08245E2Fu   // Reference result of CRC-32 operation on given data buffer.


/**
 * @brief Performs a call to function mcuxClCrc_computeCRC32
 *
 * @retval MCUXCLEXAMPLE_STATUS_OK      The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR   The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClCrc_Crc32_example)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCrc_computeCRC32(
                                            data,
                                            sizeof(data))
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_computeCRC32) != token) || (NCP_CL_CRC_REF_RESULT != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCLEXAMPLE_STATUS_OK;
}
