/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023, 2025 NXP                                            */
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
 * @example mcuxClEcc_WeierECC_DecodePoint_brainpoolP384r1_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClCore_Examples.h>
#include <mcuxClSession.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClEcc.h>
#include <mcuxCsslFlowProtection.h>


/* Compressed point on brainpoolP384r1 according to encoding specified in SEC 1: Elliptic Curve Cryptography */
static const uint8_t pCompressedPoint[MCUXCLECC_WEIERECC_BRAINPOOLP384R1_SIZE_ENCPOINT_SEC_COMPRESSED] =
{
    /* Q = ((0x02 | LSBit(y)) || x) with
     * LSBit of y = 0x01 */
    0x03u,
    /* x = 0x6460f955efdcbf3bf7393081ddf04a64747781bc8956c1e5ff47be522f7f758244ae054e91e8aa160c76dc7302bcf181 */
    0x64u, 0x60u, 0xF9u, 0x55u, 0xEFu, 0xDCu, 0xBFu, 0x3Bu,
    0xF7u, 0x39u, 0x30u, 0x81u, 0xDDu, 0xF0u, 0x4Au, 0x64u,
    0x74u, 0x77u, 0x81u, 0xBCu, 0x89u, 0x56u, 0xC1u, 0xE5u,
    0xFFu, 0x47u, 0xBEu, 0x52u, 0x2Fu, 0x7Fu, 0x75u, 0x82u,
    0x44u, 0xAEu, 0x05u, 0x4Eu, 0x91u, 0xE8u, 0xAAu, 0x16u,
    0x0Cu, 0x76u, 0xDCu, 0x73u, 0x02u, 0xBCu, 0xF1u, 0x81u
};

/* Reference for the decompressed point */
static const uint8_t pRefDecodedPoint[MCUXCLECC_WEIERECC_BRAINPOOLP384R1_SIZE_PRIMEP * 2u] =
{
    /* Q = 7*G = (x,y) with
     * x = 0x6460f955efdcbf3bf7393081ddf04a64747781bc8956c1e5ff47be522f7f758244ae054e91e8aa160c76dc7302bcf181 (big endian) */
    0x64u, 0x60u, 0xF9u, 0x55u, 0xEFu, 0xDCu, 0xBFu, 0x3Bu,
    0xF7u, 0x39u, 0x30u, 0x81u, 0xDDu, 0xF0u, 0x4Au, 0x64u,
    0x74u, 0x77u, 0x81u, 0xBCu, 0x89u, 0x56u, 0xC1u, 0xE5u,
    0xFFu, 0x47u, 0xBEu, 0x52u, 0x2Fu, 0x7Fu, 0x75u, 0x82u,
    0x44u, 0xAEu, 0x05u, 0x4Eu, 0x91u, 0xE8u, 0xAAu, 0x16u,
    0x0Cu, 0x76u, 0xDCu, 0x73u, 0x02u, 0xBCu, 0xF1u, 0x81u,
    /* y = 0x7a30d2af9219e43d33be0b515a36f3c95c17b17dcad568ef85f51eae54657c72ed3ca9972dd90da5fc54207824db4187 (big endian) */
    0x7Au, 0x30u, 0xD2u, 0xAFu, 0x92u, 0x19u, 0xE4u, 0x3Du,
    0x33u, 0xBEu, 0x0Bu, 0x51u, 0x5Au, 0x36u, 0xF3u, 0xC9u,
    0x5Cu, 0x17u, 0xB1u, 0x7Du, 0xCAu, 0xD5u, 0x68u, 0xEFu,
    0x85u, 0xF5u, 0x1Eu, 0xAEu, 0x54u, 0x65u, 0x7Cu, 0x72u,
    0xEDu, 0x3Cu, 0xA9u, 0x97u, 0x2Du, 0xD9u, 0x0Du, 0xA5u,
    0xFCu, 0x54u, 0x20u, 0x78u, 0x24u, 0xDBu, 0x41u, 0x87u
};


#define MAX_CPUWA_SIZE  MCUXCLECC_WEIERECC_DECODEPOINT_WACPU_SIZE
#define MAX_PKCWA_SIZE  MCUXCLECC_WEIERECC_DECODEPOINT_WAPKC_SIZE_384
/**
 * Performs an example point decoding of a point on brainpoolP384r1, which is compressed according to
 * SEC 1: Elliptic Curve Cryptography, using the mcuxClEcc component.
 * @retval MCUXCLEXAMPLE_STATUS_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR The example code failed
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_WeierECC_DecodePoint_brainpoolP384r1_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t pSession = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(pSession, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);


    /**************************************************************************/
    /* Decode the compressed point on brainpoolP384r1                         */
    /**************************************************************************/

    uint8_t pDecodedPoint[MCUXCLECC_WEIERECC_BRAINPOOLP384R1_SIZE_PRIMEP * 2u] = {0};
    MCUXCLBUFFER_INIT(buffDecodedPoint, NULL, pDecodedPoint, (MCUXCLECC_WEIERECC_BRAINPOOLP384R1_SIZE_PRIMEP * 2u));
    MCUXCLBUFFER_INIT_RO(buffCompressedPoint, NULL, pCompressedPoint, sizeof(pCompressedPoint));
    
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(decodePoint_status, decodePoint_token, mcuxClEcc_WeierECC_DecodePoint(
                                      pSession,
                                      buffCompressedPoint,
                                      buffDecodedPoint,
                                      mcuxClEcc_WeierECC_PointEncType_SEC,
                                      MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER()
                                      (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_brainpoolP384r1
                                      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER())
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_WeierECC_DecodePoint) != decodePoint_token) || (MCUXCLECC_STATUS_OK != decodePoint_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Compare the decoded point to the reference result                      */
    /**************************************************************************/

    if(!mcuxClCore_assertEqual(pDecodedPoint, pRefDecodedPoint, MCUXCLECC_WEIERECC_BRAINPOOLP384R1_SIZE_PRIMEP * 2u))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }


    /**************************************************************************/
    /* Clean session                                                          */
    /**************************************************************************/
    
    if(!mcuxClExample_Session_Clean(pSession))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
