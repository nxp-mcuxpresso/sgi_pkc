/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2025 NXP                                                 */
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

/** @example  mcuxCsslMemory_Copy_example.c
 *  @brief Example constant-time memory copy (CSSL component mcuxCsslMemory) */

#include <mcuxClToolchain.h>
#include <stdbool.h>
#include <stdint.h>
#include <mcuxCsslMemory.h>
#include <mcuxCsslMemory_Examples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslParamIntegrity.h>

#define EXIT_CODE_ERROR false   ///< example return code in case an error occurred
#define EXIT_CODE_OK    true    ///< example return code in case of successful operation

MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_Copy_example)
{   
    /* Define data arrays */
    ALIGNED uint8_t arr1[] = {0xe4u, 0xf9u, 0x26u, 0x4cu, 0x65u, 0xe2u, 0x13u, 0xa3u,
                              0x9au, 0x40u, 0xd7u, 0x87u, 0xccu, 0x0bu, 0x31u, 0x18u,
                              0xacu, 0x55u, 0xb5u, 0x7du, 0x06u, 0x7fu, 0xceu, 0xe4u,
                              0xb2u, 0x7eu, 0xd5u, 0xaau, 0x90u, 0x9au, 0x42u, 0x56u,
                              0x76u};

    ALIGNED uint8_t arr2[sizeof(arr1)] = {0u};


    /* Provoke buffer overflow => should return invalid parameter error */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(copyResult, copyToken, mcuxCsslMemory_Copy(
    /*  mcuxCsslParamIntegrity_Checksum_t chk,*/ MCUX_CSSL_PI_PROTECT(arr1, arr2, sizeof(arr1), sizeof(arr1) + 1u),
    /*  void const * src,                    */ arr1,
    /*  void * dst,                          */ arr2,
    /*  uint32_t dstLength,                    */ sizeof(arr1),
    /*  uint32_t length                        */ sizeof(arr1) + 1u));
    
    /* Check the return code of mcuxCsslMemory_Copy */
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Copy) != copyToken) || (MCUXCSSLMEMORY_STATUS_INVALID_PARAMETER != copyResult))
    {
        return EXIT_CODE_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Try to copy nothing (length = 0 bytes) => should return success */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(copyResult1, copyToken1, mcuxCsslMemory_Copy(
    /*  mcuxCsslParamIntegrity_Checksum_t chk,*/ MCUX_CSSL_PI_PROTECT(arr1, arr2, sizeof(arr1), 0u),
    /*  void const * src,                    */ arr1,
    /*  void * dst,                          */ arr2,
    /*  uint32_t dstLength,                    */ sizeof(arr1),
    /*  uint32_t length                        */ 0u));
    
    /* Check the return code of mcuxCsslMemory_Copy */
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Copy) != copyToken1) || (MCUXCSSLMEMORY_STATUS_OK != copyResult1))
    {
        return EXIT_CODE_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Copy arr1 to arr2 => should return success */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(copyResult2, copyToken2, mcuxCsslMemory_Copy(
    /*  mcuxCsslParamIntegrity_Checksum_t chk,*/ MCUX_CSSL_PI_PROTECT(arr1, arr2, sizeof(arr1), sizeof(arr1)),
    /*  void const * src,                    */ arr1,
    /*  void * dst,                          */ arr2,
    /*  uint32_t dstLength,                    */ sizeof(arr1),
    /*  uint32_t length                        */ sizeof(arr1)));
    
    /* Check the return code of mcuxCsslMemory_Copy */
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Copy) != copyToken2) || (MCUXCSSLMEMORY_STATUS_OK != copyResult2))
    {
        return EXIT_CODE_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* No error occurred during execution, exit with EXIT_CODE_OK */
    return EXIT_CODE_OK;
}
