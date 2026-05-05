/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * @example mcuxClXofModes_shake_256_oneshot_example.c
 * @brief mcuxClXofModes example application
 */

#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxClXof.h>
#include <mcuxClXofModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

/* Source of this example data is NIST CAVP SHAKE256VariableOut.rsp */

static const uint8_t data[] = {
    0x8du, 0x80u, 0x01u, 0xe2u, 0xc0u, 0x96u, 0xf1u, 0xb8u, 0x8eu, 0x7cu, 0x92u, 0x24u, 0xa0u, 0x86u, 0xefu, 0xd4u,
    0x79u, 0x7fu, 0xbfu, 0x74u, 0xa8u, 0x03u, 0x3au, 0x2du, 0x42u, 0x2au, 0x2bu, 0x6bu, 0x8fu, 0x67u, 0x47u, 0xe4u
};

#define MCUXCLXOF_EXAMPLE_SHAKE_256_OUTSIZE 250u
static const uint32_t outSize = MCUXCLXOF_EXAMPLE_SHAKE_256_OUTSIZE; // arbitrary output size in bytes

static const uint8_t expectedOutput[MCUXCLXOF_EXAMPLE_SHAKE_256_OUTSIZE] = {
    0x2eu, 0x97u, 0x5fu, 0x6au, 0x8au, 0x14u, 0xf0u, 0x70u, 0x4du, 0x51u, 0xb1u, 0x36u, 0x67u, 0xd8u, 0x19u, 0x5cu,
    0x21u, 0x9fu, 0x71u, 0xe6u, 0x34u, 0x56u, 0x96u, 0xc4u, 0x9fu, 0xa4u, 0xb9u, 0xd0u, 0x8eu, 0x92u, 0x25u, 0xd3u,
    0xd3u, 0x93u, 0x93u, 0x42u, 0x51u, 0x52u, 0xc9u, 0x7eu, 0x71u, 0xddu, 0x24u, 0x60u, 0x1cu, 0x11u, 0xabu, 0xcfu,
    0xa0u, 0xf1u, 0x2fu, 0x53u, 0xc6u, 0x80u, 0xbdu, 0x3au, 0xe7u, 0x57u, 0xb8u, 0x13u, 0x4au, 0x9cu, 0x10u, 0xd4u,
    0x29u, 0x61u, 0x58u, 0x69u, 0x21u, 0x7fu, 0xddu, 0x58u, 0x85u, 0xc4u, 0xdbu, 0x17u, 0x49u, 0x85u, 0x70u, 0x3au,
    0x6du, 0x6du, 0xe9u, 0x4au, 0x66u, 0x7eu, 0xacu, 0x30u, 0x23u, 0x44u, 0x3au, 0x83u, 0x37u, 0xaeu, 0x1bu, 0xc6u,
    0x01u, 0xb7u, 0x6du, 0x7du, 0x38u, 0xecu, 0x3cu, 0x34u, 0x46u, 0x31u, 0x05u, 0xf0u, 0xd3u, 0x94u, 0x9du, 0x78u,
    0xe5u, 0x62u, 0xa0u, 0x39u, 0xe4u, 0x46u, 0x95u, 0x48u, 0xb6u, 0x09u, 0x39u, 0x5du, 0xe5u, 0xa4u, 0xfdu, 0x43u,
    0xc4u, 0x6cu, 0xa9u, 0xfdu, 0x6eu, 0xe2u, 0x9au, 0xdau, 0x5eu, 0xfcu, 0x07u, 0xd8u, 0x4du, 0x55u, 0x32u, 0x49u,
    0x45u, 0x0du, 0xabu, 0x4au, 0x49u, 0xc4u, 0x83u, 0xdeu, 0xd2u, 0x50u, 0xc9u, 0x33u, 0x8fu, 0x85u, 0xcdu, 0x93u,
    0x7au, 0xe6u, 0x6bu, 0xb4u, 0x36u, 0xf3u, 0xb4u, 0x02u, 0x6eu, 0x85u, 0x9fu, 0xdau, 0x1cu, 0xa5u, 0x71u, 0x43u,
    0x2fu, 0x3bu, 0xfcu, 0x09u, 0xe7u, 0xc0u, 0x3cu, 0xa4u, 0xd1u, 0x83u, 0xb7u, 0x41u, 0x11u, 0x1cu, 0xa0u, 0x48u,
    0x3du, 0x0eu, 0xdau, 0xbcu, 0x03u, 0xfeu, 0xb2u, 0x3bu, 0x17u, 0xeeu, 0x48u, 0xe8u, 0x44u, 0xbau, 0x24u, 0x08u,
    0xd9u, 0xdcu, 0xfdu, 0x01u, 0x39u, 0xd2u, 0xe8u, 0xc7u, 0x31u, 0x01u, 0x25u, 0xaeu, 0xe8u, 0x01u, 0xc6u, 0x1au,
    0xb7u, 0x90u, 0x0du, 0x1eu, 0xfcu, 0x47u, 0xc0u, 0x78u, 0x28u, 0x17u, 0x66u, 0xf3u, 0x61u, 0xc5u, 0xe6u, 0x11u,
    0x13u, 0x46u, 0x23u, 0x5eu, 0x1du, 0xc3u, 0x83u, 0x25u, 0x66u, 0x6cu
};

MCUXCLEXAMPLE_FUNCTION(mcuxClXofModes_shake_256_oneshot_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLXOF_COMPUTE_CPU_WA_BUFFER_SIZE_MAX, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /**************************************************************************/
    /* Output computation                                                     */
    /**************************************************************************/

    uint8_t output[MCUXCLXOF_EXAMPLE_SHAKE_256_OUTSIZE];
    MCUXCLBUFFER_INIT_RW(outputBuf, session, output, sizeof(output));
    MCUXCLBUFFER_INIT_RO(dataBuf, session, data, sizeof(data));
    MCUXCLBUFFER_INIT_RO(customizationBuf, session, NULL, 0u);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(compute_result, compute_token, mcuxClXof_compute(
    /* mcuxClSession_Handle_t session:       */ session,
    /* mcuxClXof_Algo_t algorithm:           */ mcuxClXof_Algorithm_Shake_256,
    /* mcuxCl_InputBuffer_t pIn:             */ dataBuf,
    /* uint32_t inSize:                     */ sizeof(data),
    /* mcuxCl_InputBuffer_t pCustomization:  */ customizationBuf,
    /* uint32_t customizationSize:          */ 0u,
    /* mcuxCl_Buffer_t pOut                  */ outputBuf,
    /* uint32_t outSize,                    */ outSize)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_compute) != compute_token) || (MCUXCLXOF_STATUS_OK != compute_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/
    for(size_t i = 0U; i < outSize; i++)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClXof_compute")
        if(expectedOutput[i] != output[i]) // Expect that the computed output matches our expected output
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
        {
            return MCUXCLEXAMPLE_STATUS_ERROR;
        }
    }

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
