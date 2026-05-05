/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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
 * @example mcuxClEcc_ArithmeticOperation_BurmesterDesmedt_NIST_P256_example.c
 * @brief   Implementation of ECC adaptation of Burmester Desmedt Key Distribution System specified in https://doi.org/10.1007/BFb0053443
 */

#include <mcuxClSession.h>
#include <mcuxClEcc.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> /* Code flow protection */
#include <mcuxClCore_Macros.h>

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WACPU_SIZE, \
                                MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_POINTADD_WACPU_SIZE, \
                                MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_SCALARMULT_WACPU_SIZE, MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WACPU_SIZE)))
#define MAX_PKCWA_SIZE MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WAPKC_SIZE_256, \
                                MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_POINTADD_WAPKC_SIZE_256, \
                                MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_SCALARMULT_WAPKC_SIZE_256, MCUXCLECC_ARITHMETICOPERATION_SECURESCALARMULT_WAPKC_SIZE_256)))

/* U1's randomly generated private key d1 */
static const uint8_t pU1PrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY] __attribute__ ((aligned (4))) = {
  0x5Du, 0x37u, 0x8Du, 0xFDu, 0x5Cu, 0xDDu, 0x7Au, 0x37u,
  0xE7u, 0x0Fu, 0x1Au, 0xF7u, 0xFEu, 0x99u, 0xA5u, 0x16u,
  0xD4u, 0xE0u, 0xC4u, 0x34u, 0xD8u, 0x49u, 0x85u, 0xFBu,
  0x12u, 0x50u, 0x32u, 0x06u, 0x73u, 0x9Au, 0x96u, 0xF4u,
};

/* U1's public key Q1 associated with private key d1 */
static const uint8_t pU1PubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] __attribute__ ((aligned (4))) = {
  0x0Cu, 0xB2u, 0x52u, 0x2Fu, 0x18u, 0xF9u, 0xB5u, 0xA3u,
  0xADu, 0x3Au, 0xE0u, 0x99u, 0x75u, 0x5Au, 0x49u, 0xCDu,
  0xCEu, 0x4Bu, 0x05u, 0x14u, 0xB5u, 0xC6u, 0x15u, 0x07u,
  0xF0u, 0xC6u, 0x39u, 0xE7u, 0x1Au, 0xB4u, 0x4Cu, 0xDEu,
  0x68u, 0xF8u, 0xDFu, 0x58u, 0xA9u, 0xC0u, 0xF8u, 0x62u,
  0x35u, 0x9Cu, 0xB2u, 0x36u, 0xF9u, 0x29u, 0xABu, 0x9Fu,
  0x89u, 0xB1u, 0xA7u, 0xA2u, 0x34u, 0xC1u, 0xE4u, 0x57u,
  0x23u, 0xC7u, 0xE9u, 0x41u, 0x25u, 0x80u, 0x46u, 0xBBu,
};

/* U2's randomly generated private key d2 */
static const uint8_t pU2PrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY] __attribute__ ((aligned (4))) = {
  0x90u, 0xA1u, 0x2Cu, 0xEDu, 0x78u, 0x9Au, 0x4Fu, 0x82u,
  0x95u, 0xBAu, 0x2Fu, 0x79u, 0x3Du, 0x52u, 0x15u, 0xABu,
  0xDEu, 0x98u, 0x4Cu, 0x4Bu, 0x08u, 0x87u, 0xBFu, 0x6Fu,
  0x75u, 0x1Bu, 0x1Bu, 0x19u, 0xF2u, 0xFDu, 0x76u, 0x03u
};

/* U2's public key Q2 associated with private key d2 */
static const uint8_t pU2PubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] __attribute__ ((aligned (4))) = {
  0xF4u, 0x7Au, 0x9Au, 0xA6u, 0x2Du, 0x6Bu, 0x5Cu, 0x57u,
  0x1Eu, 0xC6u, 0x6Au, 0xDFu, 0x00u, 0x1Eu, 0x2Cu, 0x2Du,
  0x21u, 0x72u, 0xDEu, 0x07u, 0x2Bu, 0xA5u, 0xB9u, 0xB4u,
  0xB2u, 0xB5u, 0xC3u, 0xEBu, 0xC9u, 0x50u, 0xE0u, 0x21u,
  0x12u, 0xF9u, 0xD0u, 0xA3u, 0xA8u, 0x85u, 0x0Bu, 0x9Bu,
  0xA6u, 0xE1u, 0x4Bu, 0x3Bu, 0x7Du, 0x54u, 0xD8u, 0x7Bu,
  0xF9u, 0x82u, 0xECu, 0x38u, 0x1Bu, 0x81u, 0x5Bu, 0x7Du,
  0x9Fu, 0x29u, 0x51u, 0x9Fu, 0x52u, 0x95u, 0x24u, 0xD6u
};

/* U3's randomly generated private key d3 */
static const uint8_t pU3PrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY] __attribute__ ((aligned (4))) = {
  0x01u, 0xB9u, 0x65u, 0xB4u, 0x5Fu, 0xF3u, 0x86u, 0xF2u,
  0x8Cu, 0x12u, 0x1Cu, 0x07u, 0x7Fu, 0x1Du, 0x7Bu, 0x27u,
  0x10u, 0xACu, 0xC6u, 0xB0u, 0xCBu, 0x58u, 0xD8u, 0x66u,
  0x2Du, 0x54u, 0x93u, 0x91u, 0xDCu, 0xF5u, 0xA8u, 0x83u
};

/* U3's public key Q3 associated with private key d3 */
static const uint8_t pU3PubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] __attribute__ ((aligned (4))) = {
  0x1Fu, 0x03u, 0x8cu, 0x54u, 0x22u, 0xE8u, 0x8Eu, 0xECu,
  0x9Eu, 0x88u, 0xB8u, 0x15u, 0xE8u, 0xF6u, 0xB3u, 0xE5u,
  0x08u, 0x52u, 0x33u, 0x3Fu, 0xC4u, 0x23u, 0x13u, 0x43u,
  0x48u, 0xFCu, 0x7Du, 0x79u, 0xEFu, 0x8Eu, 0x8Au, 0x10u,
  0x43u, 0xA0u, 0x47u, 0xCBu, 0x20u, 0xE9u, 0x4Bu, 0x4Fu,
  0xFBu, 0x36u, 0x1Eu, 0xF6u, 0x89u, 0x52u, 0xB0u, 0x04u,
  0xC0u, 0x70u, 0x0Bu, 0x29u, 0x62u, 0xE0u, 0xC0u, 0x63u,
  0x5Au, 0x70u, 0x26u, 0x9Bu, 0xC7u, 0x89u, 0xB8u, 0x49u,
};

/* Const scalar 2 */
static const uint8_t pScalarTwoData[1] __attribute__ ((aligned (4))) = {0x02};

/* Const scalar 3 */
static const uint8_t pScalarThreeData[1] __attribute__ ((aligned (4))) = {0x03};

MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ArithmeticOperation_BurmesterDesmedt_NIST_P256_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /* Setup one session to be used by all functions called */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t pSession = &sessionDesc;
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(pSession,
                                              MAX_CPUWA_SIZE,
                                              MAX_PKCWA_SIZE);

  /* Allocate memory to store the broadcast Xi for each party */
  uint8_t pU1BroadcastData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {0};
  uint8_t pU2BroadcastData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {0};
  uint8_t pU3BroadcastData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {0};

  /* Allocate memory to store the calculated session key K for each party */
  uint8_t pU1SharedKeyPointData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {0};
  uint8_t pU2SharedKeyPointData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {0};
  uint8_t pU3SharedKeyPointData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {0};

  /* Allocate memory to store temporary value t */
  uint8_t pTemporaryData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = {0};


  /* Initialize buffer for U1's private key data d1 */
  MCUXCLBUFFER_INIT_RO(buffU1PrivKey, NULL, pU1PrivKeyData, sizeof(pU1PrivKeyData));
  /* Initialize buffer for U1's public key data Q1 */
  MCUXCLBUFFER_INIT_RO(buffU1PubKey, NULL, pU1PubKeyData, sizeof(pU1PubKeyData));

  /* Initialize buffer for U2's private key data d2 */
  MCUXCLBUFFER_INIT_RO(buffU2PrivKey, NULL, pU2PrivKeyData, sizeof(pU2PrivKeyData));
  /* Initialize buffer for U2's public key data Q2 */
  MCUXCLBUFFER_INIT_RO(buffU2PubKey, NULL, pU2PubKeyData, sizeof(pU2PubKeyData));

  /* Initialize buffer for U3's private key data d3 */
  MCUXCLBUFFER_INIT_RO(buffU3PrivKey, NULL, pU3PrivKeyData, sizeof(pU3PrivKeyData));
  /* Initialize buffer for U3's public key data Q3 */
  MCUXCLBUFFER_INIT_RO(buffU3PubKey, NULL, pU3PubKeyData, sizeof(pU3PubKeyData));

  /* Initialize buffers for small scalars 2 and 3 */
  MCUXCLBUFFER_INIT_RO(buffScalarTwo, NULL, pScalarTwoData, sizeof(pScalarTwoData));
  MCUXCLBUFFER_INIT_RO(buffScalarThree, NULL, pScalarThreeData, sizeof(pScalarThreeData));

  /* Initialize buffer for U1's broadcast data P1 */
  MCUXCLBUFFER_INIT_RW(buffU1Broadcast, NULL, pU1BroadcastData, sizeof(pU1BroadcastData));
  /* Initialize buffer for U2's broadcast data P2 */
  MCUXCLBUFFER_INIT_RW(buffU2Broadcast, NULL, pU2BroadcastData, sizeof(pU2BroadcastData));
  /* Initialize buffer for U3's broadcast data P3 */
  MCUXCLBUFFER_INIT_RW(buffU3Broadcast, NULL, pU3BroadcastData, sizeof(pU3BroadcastData));

  /* Initialize buffers for calculated session key K for each party */
  MCUXCLBUFFER_INIT_RW(buffU1SharedKeyPoint, NULL, pU1SharedKeyPointData, sizeof(pU1SharedKeyPointData));
  MCUXCLBUFFER_INIT_RW(buffU2SharedKeyPoint, NULL, pU2SharedKeyPointData, sizeof(pU2SharedKeyPointData));
  MCUXCLBUFFER_INIT_RW(buffU3SharedKeyPoint, NULL, pU3SharedKeyPointData, sizeof(pU3SharedKeyPointData));

  /* Initialize buffer for temporary data t */
  MCUXCLBUFFER_INIT_RW(buffTemporary, NULL, pTemporaryData, sizeof(pTemporaryData));

  /**************************************************************************/
  /* Burmester Desmedt key agreement on NIST P-256                         */
  /**************************************************************************/

  /* In example there are 3 parties in ring: U1, U2, U3 */
  /* Example can be extended to more parties */
  /* Operation are done in-place to save memory and to keep example simple */

  /**************************************************************************/
  /* Session key parts calculations                                         */
  /**************************************************************************/

  /* Session key U1's part */

  /* P1 <- Q2-Q3 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointSub_status, pointSub_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointSub,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU2PubKey,
          /* uint32_t op1Size,                                     */ sizeof(pU2PubKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU3PubKey,
          /* uint32_t op2Size,                                     */ sizeof(pU3PubKeyData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU1Broadcast,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointSub_token) ||
      (MCUXCLECC_STATUS_OK != pointSub_status) || (sizeof(pU1BroadcastData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }
  
  /* P1 = d1 * (Q2-Q3) */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_SecureScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU1PrivKey,
          /* uint32_t op1Size,                                     */ sizeof(pU1PrivKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU1Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU1BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU1Broadcast,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU1BroadcastData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }
  
  /* Session key U2's part */

  /* P2 <- Q3-Q1 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointSub_status, pointSub_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointSub,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU3PubKey,
          /* uint32_t op1Size,                                     */ sizeof(pU3PubKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU1PubKey,
          /* uint32_t op2Size,                                     */ sizeof(pU1PubKeyData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU2Broadcast,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointSub_token) ||
       (MCUXCLECC_STATUS_OK != pointSub_status) || (sizeof(pU2BroadcastData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }
  

  /* P2 = d2 * (Q3-Q1) */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_SecureScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU2PrivKey,
          /* uint32_t op1Size,                                     */ sizeof(pU2PrivKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU2Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU2BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU2Broadcast,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU2BroadcastData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }
  
  /* Session key U3's part */

  /* P3 <- Q1-Q2 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointSub_status, pointSub_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointSub,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU1PubKey,
          /* uint32_t op1Size,                                     */ sizeof(pU1PubKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU2PubKey,
          /* uint32_t op2Size,                                     */ sizeof(pU2PubKeyData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU3Broadcast,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointSub_token) ||
       (MCUXCLECC_STATUS_OK != pointSub_status) || (sizeof(pU3BroadcastData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* P3 = d3 * (Q1-Q2) */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_SecureScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU3PrivKey,
          /* uint32_t op1Size,                                     */ sizeof(pU3PrivKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU3Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU3BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU3Broadcast,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU3BroadcastData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /**************************************************************************/
  /* Session key calculations                                               */
  /**************************************************************************/

  /* U1's session key */

  /* K <- 3 * Q3 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffScalarThree,
          /* uint32_t op1Size,                                     */ sizeof(pScalarThreeData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU3PubKey,
          /* uint32_t op2Size,                                     */ sizeof(pU3PubKeyData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU1SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU1SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K <- d1 * 3 * Q3 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU1PrivKey,
          /* uint32_t op1Size,                                     */ sizeof(pU1PrivKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU1SharedKeyPoint,
          /* uint32_t op2Size,                                     */ sizeof(pU1SharedKeyPointData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU1SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU1SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* t <- 2 * P1 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffScalarTwo,
          /* uint32_t op1Size,                                     */ sizeof(pScalarTwoData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU1Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU1BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffTemporary,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU1SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K <- d1 *3 * Q3 + t = d1 * 3 * Q3 + 2 * P1 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointAdd,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU1SharedKeyPoint,
          /* uint32_t op1Size,                                     */ sizeof(pU1SharedKeyPointData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffTemporary,
          /* uint32_t op2Size,                                     */ sizeof(pTemporaryData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU1SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || (sizeof(pU1SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K = d1 * 3 * Q3 + 2 * P1 + P2 = (d1 * d2 + d2 * d3 + d3 * d1) * G */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointAdd,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU1SharedKeyPoint,
          /* uint32_t op1Size,                                     */ sizeof(pU1SharedKeyPointData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU2Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU2BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU1SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || (sizeof(pU1SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* U2's session key */
  /* K <- 2 * Q1 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointAdd,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU1PubKey,
          /* uint32_t op1Size,                                     */ sizeof(pU1PubKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU1PubKey,
          /* uint32_t op2Size,                                     */ sizeof(pU1PubKeyData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU2SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || (sizeof(pU2SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K <- 3 * Q1 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffScalarThree,
          /* uint32_t op1Size,                                     */ sizeof(pScalarThreeData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU1PubKey,
          /* uint32_t op2Size,                                     */ sizeof(pU1PubKeyData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU2SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU2SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K <- d2 * 3 * Q1 */ 
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU2PrivKey,
          /* uint32_t op1Size,                                     */ sizeof(pU2PrivKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU2SharedKeyPoint,
          /* uint32_t op2Size,                                     */ sizeof(pU2SharedKeyPointData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU2SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU2SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* t <- 2 * P2 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffScalarTwo,
          /* uint32_t op1Size,                                     */ sizeof(pScalarTwoData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU2Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU2BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffTemporary,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU1SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K <- d2 *3 * Q1 + t = d2 *3 * Q1 + 2 * P2 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointAdd,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU2SharedKeyPoint,
          /* uint32_t op1Size,                                     */ sizeof(pU2SharedKeyPointData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffTemporary,
          /* uint32_t op2Size,                                     */ sizeof(pTemporaryData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU2SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || (sizeof(pU2SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K = d2 * 3 * Q1 + 2 * P2 + P3 = (d1 * d2 + d2 * d3 + d3 * d1) * G */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointAdd,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU2SharedKeyPoint,
          /* uint32_t op1Size,                                     */ sizeof(pU2SharedKeyPointData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU3Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU3BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU2SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || (sizeof(pU2SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* U3's session key */
  /* K <- 3 * Q2 */ 
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffScalarThree,
          /* uint32_t op1Size,                                     */ sizeof(pScalarThreeData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU2PubKey,
          /* uint32_t op2Size,                                     */ sizeof(pU2PubKeyData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU3SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU3SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K <- d3 * 3 * Q2 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU3PrivKey,
          /* uint32_t op1Size,                                     */ sizeof(pU3PrivKeyData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU3SharedKeyPoint,
          /* uint32_t op2Size,                                     */ sizeof(pU3SharedKeyPointData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU3SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU3SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* t <- 2 * P3 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_ScalarMult,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffScalarTwo,
          /* uint32_t op1Size,                                     */ sizeof(pScalarTwoData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU3Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU3BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffTemporary,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != scalarMult_token) ||
       (MCUXCLECC_STATUS_OK != scalarMult_status) || (sizeof(pU1SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /* K <- d3 * 3 * Q2 + t = d3 * 3 * Q2 + 2 * P3 */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointAdd,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU3SharedKeyPoint,
          /* uint32_t op1Size,                                     */ sizeof(pU3SharedKeyPointData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffTemporary,
          /* uint32_t op2Size,                                     */ sizeof(pTemporaryData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU3SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || (sizeof(pU3SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }
  
  /* K = d3 * 3 * Q2 + 2 * P3 + P1 = (d1 * d2 + d2 * d3 + d3 * d1) * G */
  {
    uint32_t resultSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token, 
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t pSession,                       */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t arithmeticOperation,   */ mcuxClEcc_ArithmeticOperation_PointAdd,
          /* mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams, */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          /* mcuxCl_InputBuffer_t pOp1,                             */ buffU3SharedKeyPoint,
          /* uint32_t op1Size,                                     */ sizeof(pU3SharedKeyPointData),
          /* mcuxCl_InputBuffer_t pOp2,                             */ buffU1Broadcast,
          /* uint32_t op2Size,                                     */ sizeof(pU1BroadcastData),
          /* mcuxCl_Buffer_t pResult,                               */ buffU3SharedKeyPoint,
          /* uint32_t * const pResultSize                          */ &resultSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || (sizeof(pU3SharedKeyPointData) != resultSize))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  }

  /**************************************************************************/
  /* Verification and cleanup                                               */
  /**************************************************************************/

  /* Verify that U1, U2 and U3 computed the same shared key */
  if(!mcuxClCore_assertEqual(pU1SharedKeyPointData, pU2SharedKeyPointData, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  if(!mcuxClCore_assertEqual(pU2SharedKeyPointData, pU3SharedKeyPointData, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Destroy Session and cleanup Session */
  if(!mcuxClExample_Session_Clean(pSession))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
