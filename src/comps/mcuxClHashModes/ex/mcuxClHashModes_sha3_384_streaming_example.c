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
 * @example mcuxClHashModes_sha3_384_streaming_example.c
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

/* Source of this example data is NIST CAVP SHA3_384ShortMsg.rsp */

static const uint8_t data1[] = {
    0x9cu, 0x69u, 0x49u, 0x43u, 0x38u, 0x9bu, 0xdcu, 0x4eu, 0x05u, 0xadu, 0x7cu, 0x2fu, 0x63u, 0xceu, 0xacu, 0x28u
};
static const uint8_t data2[] = {
    0x20u, 0xe1u, 0xd2u, 0xd7u
};

static const uint8_t hashExpected[] = {
    0xf6u, 0x92u, 0xc0u, 0x25u, 0xc5u, 0xc5u, 0xf3u, 0xd1u, 0x27u, 0x52u, 0x13u, 0xc1u, 0xdfu, 0x9bu, 0xf9u, 0xebu, 
    0x6du, 0x21u, 0x88u, 0xedu, 0xa9u, 0x0au, 0xb5u, 0xbfu, 0xfeu, 0x63u, 0x1fu, 0x1du, 0xbfu, 0x70u, 0xebu, 0xd6u, 
    0x28u, 0xcau, 0xeeu, 0x88u, 0xb7u, 0xd1u, 0x49u, 0xe1u, 0xacu, 0x4eu, 0x26u, 0x28u, 0x73u, 0x97u, 0x9au, 0xfeu
};

MCUXCLEXAMPLE_FUNCTION(mcuxClHashModes_sha3_384_streaming_example)
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

    uint32_t context[MCUXCLHASH_CONTEXT_SIZE_SHA3_384_IN_WORDS];
    mcuxClHash_Context_t pContext = (mcuxClHash_Context_t) context;

    MCUXCLBUFFER_INIT_RO(data1Buf, session, data1, sizeof(data1));
    MCUXCLBUFFER_INIT_RO(data2Buf, session, data2, sizeof(data2));

    /**************************************************************************/
    /* Hash computation                                                       */
    /**************************************************************************/

    uint8_t hash[MCUXCLHASH_OUTPUT_SIZE_SHA3_384];
    MCUXCLBUFFER_INIT_RW(hashBuf, session, hash, sizeof(hash));
    uint32_t hashOutputSize = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result1, token1, mcuxClHash_init(
    /* mcuxCLSession_Handle_t session: */ session,
    /* mcuxClHash_Context_t context:   */ pContext,
    /* mcuxClHash_Algo_t  algo:        */ mcuxClHash_Algorithm_Sha3_384
    ));
    // mcuxClHash_init is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init) != token1) || (MCUXCLHASH_STATUS_OK != result1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result2, token2, mcuxClHash_process(
            /* mcuxCLSession_Handle_t session: */ session,
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClHash_init")
            /* mcuxClHash_Context_t context:   */ pContext,
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
            /* const uint8_t * const in:      */ data1Buf,
            /* uint32_t inLength:             */ sizeof(data1)
    ));
    // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token2) || (MCUXCLHASH_STATUS_OK != result2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result3, token3, mcuxClHash_process(
            /* mcuxCLSession_Handle_t session: */ session,
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClHash_init")
            /* mcuxClHash_Context_t context:   */ pContext,
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
            /* const uint8_t * const in:      */ data2Buf,
            /* uint32_t inLength:             */ sizeof(data2)
    ));
    // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token3) || (MCUXCLHASH_STATUS_OK != result3))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result4, token4, mcuxClHash_finish(
            /* mcuxCLSession_Handle_t session: */ session,
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_ALREADY_INITIALIZED("Initialized by mcuxClHash_init")
            /* mcuxClHash_Context_t context:   */ pContext,
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ALREADY_INITIALIZED()
            /* mcuxCl_Buffer_t pOut,        */    hashBuf,
            /* uint32_t *const pOutSize    */    &hashOutputSize
    ));
    // mcuxClHash_finish is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish) != token4) || (MCUXCLHASH_STATUS_OK != result4))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    
    if(sizeof(hash) != hashOutputSize)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/
    for(size_t i = 0U; i < sizeof(hash); i++)
    {
        if(hashExpected[i] != hash[i])  // Expect that the resulting hash matches our expected output
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
