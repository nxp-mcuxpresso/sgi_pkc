/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
