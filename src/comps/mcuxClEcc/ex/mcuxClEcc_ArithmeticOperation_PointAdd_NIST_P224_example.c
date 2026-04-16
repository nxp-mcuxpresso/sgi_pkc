/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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
 * @example mcuxClEcc_ArithmeticOperation_PointAdd_NIST_P224_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClCore_Examples.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClEcc.h>


/* First input point for point addition */
static const uint8_t pPointP1[MCUXCLECC_WEIERECC_NIST_P224_SIZE_PRIMEP * 2u] =
{
    /* P1 = 4*G = (x,y) with
     * x = 0xAE99FEEBB5D26945B54892092A8AEE02912930FA41CD114E40447301 (big endian) */
    0xAEu, 0x99u, 0xFEu, 0xEBu, 0xB5u, 0xD2u, 0x69u, 0x45u,
    0xB5u, 0x48u, 0x92u, 0x09u, 0x2Au, 0x8Au, 0xEEu, 0x02u,
    0x91u, 0x29u, 0x30u, 0xFAu, 0x41u, 0xCDu, 0x11u, 0x4Eu,
    0x40u, 0x44u, 0x73u, 0x01u,
    /* y = 0x0482580A0EC5BC47E88BC8C378632CD196CB3FA058A7114EB03054C9 (big endian) */
    0x04u, 0x82u, 0x58u, 0x0Au, 0x0Eu, 0xC5u, 0xBCu, 0x47u,
    0xE8u, 0x8Bu, 0xC8u, 0xC3u, 0x78u, 0x63u, 0x2Cu, 0xD1u,
    0x96u, 0xCBu, 0x3Fu, 0xA0u, 0x58u, 0xA7u, 0x11u, 0x4Eu,
    0xB0u, 0x30u, 0x54u, 0xC9u
};

/* Second input point for point addition */
static const uint8_t pPointP2[MCUXCLECC_WEIERECC_NIST_P224_SIZE_PRIMEP * 2u] =
{
    /* P2 = 7*G = (x,y) with
     * x = 0xDB2F6BE630E246A5CF7D99B85194B123D487E2D466B94B24A03C3E28 (big endian) */
    0xDBu, 0x2Fu, 0x6Bu, 0xE6u, 0x30u, 0xE2u, 0x46u, 0xA5u,
    0xCFu, 0x7Du, 0x99u, 0xB8u, 0x51u, 0x94u, 0xB1u, 0x23u,
    0xD4u, 0x87u, 0xE2u, 0xD4u, 0x66u, 0xB9u, 0x4Bu, 0x24u,
    0xA0u, 0x3Cu, 0x3Eu, 0x28u,
    /* y = 0x0F3A30085497F2F611EE2517B163EF8C53B715D18BB4E4808D02B963 (big endian) */
    0x0Fu, 0x3Au, 0x30u, 0x08u, 0x54u, 0x97u, 0xF2u, 0xF6u,
    0x11u, 0xEEu, 0x25u, 0x17u, 0xB1u, 0x63u, 0xEFu, 0x8Cu,
    0x53u, 0xB7u, 0x15u, 0xD1u, 0x8Bu, 0xB4u, 0xE4u, 0x80u,
    0x8Du, 0x02u, 0xB9u, 0x63u
};

/* Reference for the resulting point */
static const uint8_t pRefResult[MCUXCLECC_WEIERECC_NIST_P224_SIZE_PRIMEP * 2u] =
{
    /* 11*G = (x,y) with
     * x = 0xEF53B6294ACA431F0F3C22DC82EB9050324F1D88D377E716448E507C (big endian) */
    0xEFu, 0x53u, 0xB6u, 0x29u, 0x4Au, 0xCAu, 0x43u, 0x1Fu,
    0x0Fu, 0x3Cu, 0x22u, 0xDCu, 0x82u, 0xEBu, 0x90u, 0x50u,
    0x32u, 0x4Fu, 0x1Du, 0x88u, 0xD3u, 0x77u, 0xE7u, 0x16u,
    0x44u, 0x8Eu, 0x50u, 0x7Cu,
    /* y = 0x20B510004092E96636CFB7E32EFDED8265C266DFB754FA6D6491A6DA (big endian) */
    0x20u, 0xB5u, 0x10u, 0x00u, 0x40u, 0x92u, 0xE9u, 0x66u,
    0x36u, 0xCFu, 0xB7u, 0xE3u, 0x2Eu, 0xFDu, 0xEDu, 0x82u,
    0x65u, 0xC2u, 0x66u, 0xDFu, 0xB7u, 0x54u, 0xFAu, 0x6Du,
    0x64u, 0x91u, 0xA6u, 0xDAu
};


#define MAX_CPUWA_SIZE  MCUXCLECC_ARITHMETICOPERATION_POINTADD_WACPU_SIZE
#define MAX_PKCWA_SIZE  MCUXCLECC_ARITHMETICOPERATION_POINTADD_WAPKC_SIZE_256 /* minimal workarea size usable for a 224 bit curve */

/**
 * Performs an example point addition of two points on NIST_P224
 * @retval MCUXCLEXAMPLE_STATUS_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR The example code failed
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ArithmeticOperation_PointAdd_NIST_P224_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t pSession = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(pSession, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);


    /**************************************************************************/
    /* Add the two points P1 and P2 on NIST_P224                              */
    /**************************************************************************/

    uint8_t pResult[MCUXCLECC_WEIERECC_NIST_P224_SIZE_PRIMEP * 2u] = {0};
    uint32_t resultSize = 0u;

    MCUXCLBUFFER_INIT_RO(buffPointP1, NULL, pPointP1, sizeof(pPointP1));
    MCUXCLBUFFER_INIT_RO(buffPointP2, NULL, pPointP2, sizeof(pPointP2));
    MCUXCLBUFFER_INIT(buffResult, NULL, pResult, sizeof(pResult));

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token, 
        mcuxClEcc_ArithmeticOperation(pSession,
                                     mcuxClEcc_ArithmeticOperation_PointAdd,
                                     (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P224,
                                     buffPointP1,
                                     sizeof(pPointP1),
                                     buffPointP2,
                                     sizeof(pPointP2),
                                     buffResult,
                                     &resultSize)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || (sizeof(pResult) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Compare the resulting point to the reference result                    */
    /**************************************************************************/

    if(!mcuxClCore_assertEqual(pResult, pRefResult, MCUXCLECC_WEIERECC_NIST_P224_SIZE_PRIMEP * 2u))
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
