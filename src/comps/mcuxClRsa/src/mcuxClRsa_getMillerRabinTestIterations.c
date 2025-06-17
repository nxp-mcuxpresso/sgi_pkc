/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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

/** @file  mcuxClRsa_getMillerRabinTestIterations.c
 *  @brief Function returns the minimum number of Miller-Rabin test iterations for given
 *  prime bit length.
 *
 */

#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_getMillerRabinTestIterations)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClRsa_getMillerRabinTestIterations(const uint32_t primeBitLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_getMillerRabinTestIterations);
  
  uint32_t numberMillerRabinTestIterations = 11u; /* init value for 512b prime */
  if(1024u == primeBitLength)
  {
    numberMillerRabinTestIterations = 6u;
  }
  if(1536u == primeBitLength)
  {
    numberMillerRabinTestIterations = 4u;
  }
  else if(2048u == primeBitLength)
  {
    numberMillerRabinTestIterations = 3u;
  }
  else if(3072u == primeBitLength)
  {
    numberMillerRabinTestIterations = 2u;
  }
  else if(4096u == primeBitLength)
  {
    numberMillerRabinTestIterations = 2u;
  }
  else
  {
    /* intentionally do nothing */
  }
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_getMillerRabinTestIterations, numberMillerRabinTestIterations);
}
