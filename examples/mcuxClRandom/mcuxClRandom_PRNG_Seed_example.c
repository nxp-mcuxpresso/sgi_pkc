/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
 * @example mcuxClRandom_PRNG_Seed_example.c
 * @brief   Example for the mcuxClRandom component with seeding for Prng
 */

#include <mcuxClCore_Examples.h>            // Defines and assertions for examples
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClToolchain.h>

#include <mcuxClBuffer.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClRandom.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>

#define randomDataSize (16u)
#define randomDataWordSize ((randomDataSize) / sizeof(uint32_t))

/** Performs an example usage of the mcuxClRandom component
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClRandom_PRNG_Seed_example)
{
  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /**************************************************************************/
  /* In mcuxClSession_init(), the PRNG seed will be reseeded.                */
  /* A reseed is neccessary after an SGI restart/flush because the seed is  */
  /* initialized at 0x00.                                                   */
  /**************************************************************************/
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRANDOM_NCINIT_WACPU_SIZE, 0u);

  /* Initialize PRNG. This initializes PRNG in normal / unpatched mode */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("session->apiCall is not NULL when accessed")
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(nci_status, nci_token, mcuxClRandom_ncInit(session));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != nci_token) || (MCUXCLRANDOM_STATUS_OK != nci_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Generate data for the first time                                       */
  /**************************************************************************/

  uint32_t pPrngData1[randomDataWordSize];
  MCUXCLBUFFER_INIT(pPrngBuffer1, session, pPrngData1, randomDataSize);

  /* Generate non cryptographic random values. */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
    ncg_status1,
    ncg_token1,
    mcuxClRandom_ncGenerate(session, pPrngBuffer1, randomDataSize)
  );
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate) != ncg_token1) || (MCUXCLRANDOM_STATUS_OK != ncg_status1))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Reseed the PRNG                                                        */
  /**************************************************************************/

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ncr_status, ncr_token, mcuxClRandom_ncReseed(session));
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncReseed) != ncr_token) || (MCUXCLRANDOM_STATUS_OK != ncr_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Generate data for the second time                                      */
  /**************************************************************************/

  uint8_t pPrngData2[randomDataSize];
  MCUXCLBUFFER_INIT(pPrngBuffer2, session, pPrngData2, randomDataSize);

  /* Generate non cryptographic random values. */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
    ncg_status2,
    ncg_token2,
    mcuxClRandom_ncGenerate(session, pPrngBuffer2, randomDataSize)
  );
  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate) != ncg_token2) || (MCUXCLRANDOM_STATUS_OK != ncg_status2))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /**************************************************************************/
  /* Cleanup                                                                */
  /**************************************************************************/

  /** Destroy Session and cleanup Session **/
  if(!mcuxClExample_Session_Clean(session))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  return MCUXCLEXAMPLE_STATUS_OK;
}
