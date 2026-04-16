/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @example mcuxClEcc_ArithmeticOperation_SecureScalarMult_secp521r1_example.c
 * @brief   Example for the mcuxClEcc component
 */

#include <mcuxClCore_Examples.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClEcc.h>
#include <mcuxCsslFlowProtection.h>


/* input scalar k for scalar multiplication */
static const uint8_t pScalar[8u] =
{
    /* k = 0x230fda505b587d47 (big endian) */
    0x23u, 0x0Fu, 0xDAu, 0x50u, 0x5Bu, 0x58u, 0x7Du, 0x47u,
};

/* input point P for scalar multiplication */
static const uint8_t pPointP[MCUXCLECC_WEIERECC_SECP521R1_SIZE_PRIMEP * 2u] =
{
    /* P = 14*G = (x,y) with
     * x = 0x01875BC7DC551B1B65A9E1B8CCFAAF84DED1958B401494116A2FD4FB0BABE0B3199974FC06C8B897222D79DF3E4B7BC744AA6767F6B812EFBF5D2C9E682DD3432D74 (big endian) */
    0x01u, 0x87u, 0x5Bu, 0xC7u, 0xDCu, 0x55u, 0x1Bu, 0x1Bu,
    0x65u, 0xA9u, 0xE1u, 0xB8u, 0xCCu, 0xFAu, 0xAFu, 0x84u,
    0xDEu, 0xD1u, 0x95u, 0x8Bu, 0x40u, 0x14u, 0x94u, 0x11u,
    0x6Au, 0x2Fu, 0xD4u, 0xFBu, 0x0Bu, 0xABu, 0xE0u, 0xB3u,
    0x19u, 0x99u, 0x74u, 0xFCu, 0x06u, 0xC8u, 0xB8u, 0x97u,
    0x22u, 0x2Du, 0x79u, 0xDFu, 0x3Eu, 0x4Bu, 0x7Bu, 0xC7u,
    0x44u, 0xAAu, 0x67u, 0x67u, 0xF6u, 0xB8u, 0x12u, 0xEFu,
    0xBFu, 0x5Du, 0x2Cu, 0x9Eu, 0x68u, 0x2Du, 0xD3u, 0x43u,
    0x2Du, 0x74u,
    /* y = 0x005CA4923575DACB5BD2D66290BBABB4BDFB8470122B8E51826A0847CE9B86D7ED62D07781B1B4F3584C11E89BF1D133DC0D5B690F53A87C84BE41669F852700D54A (big endian) */
    0x00u, 0x5Cu, 0xA4u, 0x92u, 0x35u, 0x75u, 0xDAu, 0xCBu,
    0x5Bu, 0xD2u, 0xD6u, 0x62u, 0x90u, 0xBBu, 0xABu, 0xB4u,
    0xBDu, 0xFBu, 0x84u, 0x70u, 0x12u, 0x2Bu, 0x8Eu, 0x51u,
    0x82u, 0x6Au, 0x08u, 0x47u, 0xCEu, 0x9Bu, 0x86u, 0xD7u,
    0xEDu, 0x62u, 0xD0u, 0x77u, 0x81u, 0xB1u, 0xB4u, 0xF3u,
    0x58u, 0x4Cu, 0x11u, 0xE8u, 0x9Bu, 0xF1u, 0xD1u, 0x33u,
    0xDCu, 0x0Du, 0x5Bu, 0x69u, 0x0Fu, 0x53u, 0xA8u, 0x7Cu,
    0x84u, 0xBEu, 0x41u, 0x66u, 0x9Fu, 0x85u, 0x27u, 0x00u,
    0xD5u, 0x4Au
};

/* Reference for the resulting point */
static const uint8_t pRefResult[MCUXCLECC_WEIERECC_SECP521R1_SIZE_PRIMEP * 2u] =
{
    /* x = 0x018DF374C711306D6E02DE2C34C98F1350534C376C961D365D0D1D70D79708E3E1BEEBD1C1ECCE8C883F9C756DD7D96DCF571D95D5A516E672DE80236184C61A77B4 (big endian) */
    0x01u, 0x8Du, 0xF3u, 0x74u, 0xC7u, 0x11u, 0x30u, 0x6Du,
    0x6Eu, 0x02u, 0xDEu, 0x2Cu, 0x34u, 0xC9u, 0x8Fu, 0x13u,
    0x50u, 0x53u, 0x4Cu, 0x37u, 0x6Cu, 0x96u, 0x1Du, 0x36u,
    0x5Du, 0x0Du, 0x1Du, 0x70u, 0xD7u, 0x97u, 0x08u, 0xE3u,
    0xE1u, 0xBEu, 0xEBu, 0xD1u, 0xC1u, 0xECu, 0xCEu, 0x8Cu,
    0x88u, 0x3Fu, 0x9Cu, 0x75u, 0x6Du, 0xD7u, 0xD9u, 0x6Du,
    0xCFu, 0x57u, 0x1Du, 0x95u, 0xD5u, 0xA5u, 0x16u, 0xE6u,
    0x72u, 0xDEu, 0x80u, 0x23u, 0x61u, 0x84u, 0xC6u, 0x1Au,
    0x77u, 0xB4u,
    /* Y = 0x01F1B310DDCD26F683DFD23E84C7CA8522698C27D7DD6EB8FBDDA3A0036A215EADF0C33B975396A72FF6002A568E57611469CD4C78927617D1AF5A3E8E7674182F4E (big endian) */
    0x01u, 0xF1u, 0xB3u, 0x10u, 0xDDu, 0xCDu, 0x26u, 0xF6u,
    0x83u, 0xDFu, 0xD2u, 0x3Eu, 0x84u, 0xC7u, 0xCAu, 0x85u,
    0x22u, 0x69u, 0x8Cu, 0x27u, 0xD7u, 0xDDu, 0x6Eu, 0xB8u,
    0xFBu, 0xDDu, 0xA3u, 0xA0u, 0x03u, 0x6Au, 0x21u, 0x5Eu,
    0xADu, 0xF0u, 0xC3u, 0x3Bu, 0x97u, 0x53u, 0x96u, 0xA7u,
    0x2Fu, 0xF6u, 0x00u, 0x2Au, 0x56u, 0x8Eu, 0x57u, 0x61u,
    0x14u, 0x69u, 0xCDu, 0x4Cu, 0x78u, 0x92u, 0x76u, 0x17u,
    0xD1u, 0xAFu, 0x5Au, 0x3Eu, 0x8Eu, 0x76u, 0x74u, 0x18u,
    0x2Fu, 0x4Eu
};


#define MAX_CPUWA_SIZE  MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WACPU_SIZE
#define MAX_PKCWA_SIZE  MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WAPKC_SIZE_640 /* minimal workarea size usable for a 521 bit curve */

/**
 * Performs an example scalar multiplication on secp521r1
 * @retval MCUXCLEXAMPLE_STATUS_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR The example code failed
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ArithmeticOperation_SecureScalarMult_secp521r1_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t pSession = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(pSession, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);


    /**************************************************************************/
    /* Perform scalar multiplication k*P on secp521r1                         */
    /**************************************************************************/

    uint8_t pResult[MCUXCLECC_WEIERECC_SECP521R1_SIZE_PRIMEP * 2u] = {0};
    uint32_t resultSize = 0u;

    MCUXCLBUFFER_INIT_RO(buffScalar, NULL, pScalar, sizeof(pScalar));
    MCUXCLBUFFER_INIT_RO(buffPointP, NULL, pPointP, sizeof(pPointP));
    MCUXCLBUFFER_INIT(buffResult, NULL, pResult, sizeof(pResult));

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(secureScalarMult_status, secureScalarMult_token, 
        mcuxClEcc_ArithmeticOperation(pSession,
                                     mcuxClEcc_ArithmeticOperation_SecureScalarMult,
                                     (mcuxClEcc_Weier_DomainParams_t *)&mcuxClEcc_Weier_DomainParams_secp521r1,
                                     buffScalar,
                                     sizeof(pScalar),
                                     buffPointP,
                                     sizeof(pPointP),
                                     buffResult,
                                     &resultSize)
    );
    
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != secureScalarMult_token) ||
       (MCUXCLECC_STATUS_OK != secureScalarMult_status) || (sizeof(pResult) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Compare the resulting point to the reference result                    */
    /**************************************************************************/

    if(!mcuxClCore_assertEqual(pResult, pRefResult, MCUXCLECC_WEIERECC_SECP521R1_SIZE_PRIMEP * 2u))
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
