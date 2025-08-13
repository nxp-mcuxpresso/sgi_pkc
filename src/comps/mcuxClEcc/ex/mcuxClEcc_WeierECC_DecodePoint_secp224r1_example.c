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

/**
 * @example mcuxClEcc_WeierECC_DecodePoint_secp224r1_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClCore_Examples.h>
#include <mcuxClSession.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClEcc.h>
#include <mcuxCsslFlowProtection.h>


/* Compressed point on secp224r1 according to encoding specified in SEC 1: Elliptic Curve Cryptography */
static const uint8_t pCompressedPoint[MCUXCLECC_WEIERECC_SECP224R1_SIZE_ENCPOINT_SEC_COMPRESSED] =
{
    /* Q = ((0x02 | LSBit(y)) || x) with
     * LSBit of y = 0x01 */
    0x03u,
    /* x = 0x4340025ad933f30a651a05ea93a0732d7d9f6666d99e2d8716c45dcd */
    0x43u, 0x40u, 0x02u, 0x5Au, 0xD9u, 0x33u, 0xF3u, 0x0Au,
    0x65u, 0x1Au, 0x05u, 0xEAu, 0x93u, 0xA0u, 0x73u, 0x2Du,
    0x7Du, 0x9Fu, 0x66u, 0x66u, 0xD9u, 0x9Eu, 0x2Du, 0x87u,
    0x16u, 0xC4u, 0x5Du, 0xCDu

};

/* Reference for the decompressed point */
static const uint8_t pRefDecodedPoint[MCUXCLECC_WEIERECC_SECP224R1_SIZE_PRIMEP * 2u] =
{
    /* Q = 0x102029a7c2e4ae8d8afe7b64b42065c3983d5d6cd968bdbb588608d1 * G = (x,y) with
     * x = 0x4340025ad933f30a651a05ea93a0732d7d9f6666d99e2d8716c45dcd (big endian) */
    0x43u, 0x40u, 0x02u, 0x5Au, 0xD9u, 0x33u, 0xF3u, 0x0Au,
    0x65u, 0x1Au, 0x05u, 0xEAu, 0x93u, 0xA0u, 0x73u, 0x2Du,
    0x7Du, 0x9Fu, 0x66u, 0x66u, 0xD9u, 0x9Eu, 0x2Du, 0x87u,
    0x16u, 0xC4u, 0x5Du, 0xCDu,
    /* y = 0x15563d61534f834fb38d152c2f09538de07ea201c01a94a636321aef (big endian) */
    0x15u, 0x56u, 0x3Du, 0x61u, 0x53u, 0x4Fu, 0x83u, 0x4Fu,
    0xB3u, 0x8Du, 0x15u, 0x2Cu, 0x2Fu, 0x09u, 0x53u, 0x8Du,
    0xE0u, 0x7Eu, 0xA2u, 0x01u, 0xC0u, 0x1Au, 0x94u, 0xA6u,
    0x36u, 0x32u, 0x1Au, 0xEFu
};


#define MAX_CPUWA_SIZE  MCUXCLECC_WEIERECC_DECODEPOINT_WACPU_SIZE
#define MAX_PKCWA_SIZE  MCUXCLECC_WEIERECC_DECODEPOINT_WAPKC_SIZE_256
/**
 * Performs an example point decoding of a point on secp224r1, which is compressed according to
 * SEC 1: Elliptic Curve Cryptography, using the mcuxClEcc component.
 * @retval MCUXCLEXAMPLE_STATUS_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR The example code failed
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_WeierECC_DecodePoint_secp224r1_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t pSession = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(pSession, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /**************************************************************************/
    /* Decode the compressed point on secp224r1                               */
    /**************************************************************************/

    uint8_t pDecodedPoint[MCUXCLECC_WEIERECC_SECP224R1_SIZE_PRIMEP * 2u] = {0u};
    MCUXCLBUFFER_INIT(buffDecodedPoint, NULL, pDecodedPoint, (MCUXCLECC_WEIERECC_SECP224R1_SIZE_PRIMEP * 2u));
    MCUXCLBUFFER_INIT_RO(buffCompressedPoint, NULL, pCompressedPoint, sizeof(pCompressedPoint));
    
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(decodePoint_status, decodePoint_token, mcuxClEcc_WeierECC_DecodePoint(
                                      pSession,
                                      buffCompressedPoint,
                                      buffDecodedPoint,
                                      mcuxClEcc_WeierECC_PointEncType_SEC,
                                      MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER()
                                      (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_secp224r1
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

    if(!mcuxClCore_assertEqual(pDecodedPoint, pRefDecodedPoint, MCUXCLECC_WEIERECC_SECP224R1_SIZE_PRIMEP * 2u))
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
