/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023 NXP                                                 */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
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
