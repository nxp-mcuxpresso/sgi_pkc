/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/**
 * @example mcuxClHashModes_sha3_512_oneshot_example.c
 * @brief mcuxClHashModes example application
 */

#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxClHash.h>             // Interface to the entire mcuxClHash component
#include <mcuxClHashModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

/* Source of this example data is NIST CAVP SHA3_512ShortMsg.rsp */

static const uint8_t data[] = {
    0xd7u, 0xd5u, 0x36u, 0x33u, 0x50u, 0x70u, 0x9eu, 0x96u, 0x93u, 0x9eu, 0x6bu, 0x68u, 0xb3u, 0xbbu, 0xdeu, 0xf6u,
    0x99u, 0x9au, 0xc8u, 0xd9u
};

static const uint8_t hashExpected[] = {
    0x7au, 0x46u, 0xbeu, 0xcau, 0x55u, 0x3fu, 0xffu, 0xa8u, 0x02u, 0x1bu, 0x09u, 0x89u, 0xf4u, 0x0au, 0x65u, 0x63u,
    0xa8u, 0xafu, 0xb6u, 0x41u, 0xe8u, 0x13u, 0x30u, 0x90u, 0xbcu, 0x03u, 0x4au, 0xb6u, 0x76u, 0x3eu, 0x96u, 0xd7u,
    0xb7u, 0xa0u, 0xdau, 0x4du, 0xe3u, 0xabu, 0xd5u, 0xa6u, 0x7du, 0x80u, 0x85u, 0xf7u, 0xc2u, 0x8bu, 0x21u, 0xa2u,
    0x4au, 0xefu, 0xb3u, 0x59u, 0xc3u, 0x7fu, 0xacu, 0x61u, 0xd3u, 0xa5u, 0x37u, 0x4bu, 0x4bu, 0x1fu, 0xb6u, 0xbbu
};

MCUXCLEXAMPLE_FUNCTION(mcuxClHashModes_sha3_512_oneshot_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLHASH_MAX_CPU_WA_BUFFER_SIZE, MCUXCLRANDOM_NCINIT_WACPU_SIZE), 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /**************************************************************************/
    /* Hash computation                                                       */
    /**************************************************************************/

    uint8_t hash[MCUXCLHASH_OUTPUT_SIZE_SHA3_512];
    MCUXCLBUFFER_INIT_RW(hashBuf, session, hash, sizeof(hash));
    MCUXCLBUFFER_INIT_RO(dataBuf, session, data, sizeof(data));
    uint32_t hashOutputSize = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_compute, token_compute, mcuxClHash_compute(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClHash_Algo_t algorithm:    */ mcuxClHash_Algorithm_Sha3_512,
    /* mcuxCl_InputBuffer_t pIn:       */ dataBuf,
    /* uint32_t inSize:               */ sizeof(data),
    /* mcuxCl_Buffer_t pOut            */ hashBuf,
    /* uint32_t *const pOutSize,      */ &hashOutputSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != token_compute) || (MCUXCLHASH_STATUS_OK != result_compute))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(hashOutputSize != sizeof(hash))
    {
       return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/
    for(size_t i = 0u; i < sizeof(hash); i++)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by MCUXCLBUFFER_INIT_RW")
        if(hashExpected[i] != hash[i])  // Expect that the resulting hash matches our expected output
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
