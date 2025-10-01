/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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
 * @example mcuxCsslFlowProtection_Loop_example.c
 * @brief   Example for the Loop functionality of the Flow Protection component
 */

#include <mcuxClToolchain.h>
#include <mcuxCsslExamples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslAnalysis.h>

#define ITERATION_COUNT 10U

/****************************************************************************/
/* Defines                                                                  */
/****************************************************************************/

#define MCUXCLCSSLFLOWPROTECTION_OK            0x2EDEU
#define MCUXCLCSSLFLOWPROTECTION_NOT_OK        0x89ADU
#define MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK  0xF0FAU

/****************************************************************************/
/* Protected function declarations                                          */
/****************************************************************************/

MCUX_CSSL_FP_FUNCTION_DECL(functionLoop)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionLoop(void);

/****************************************************************************/
/* Protected function definition                                            */
/****************************************************************************/

/* FP_LOOP macros can only be used from within flow protected functions.
 * To define a flow prtected function, MCUX_CSSL_FP_FUNCTION_DEF and
 * MCUX_CSSL_FP_PROTECTED_TYPE are used. For function declaration use
 * MCUX_CSSL_FP_FUNCTION_DECL and MCUX_CSSL_FP_PROTECTED_TYPE.
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionLoop)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionLoop(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionLoop);

  volatile uint8_t test = 0xA0u;

  /* MCUX_CSSL_FP_LOOP_DECL sets "testLoop" as the loop identifier.
   * it is later used by MCUX_CSSL_FP_LOOP_ITERATION and
   * MCUX_CSSL_FP_LOOP_ITERATIONS to count iterations and set an
   * expected iteration count. */
  MCUX_CSSL_FP_LOOP_DECL(testLoop);
  for (uint32_t i = 0u; i < ITERATION_COUNT; i++)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("test cannot overflow with 0xA0u as starting value and 10 iterations.")
    test++;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_LOOP_ITERATION(testLoop);
  }

  /* MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK performs the flow protection check
   * and either returns MCUXCLCSSLFLOWPROTECTION_OK or MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK
   * extended with a flow protection token depending on the outcome.
   * MCUX_CSSL_FP_LOOP_ITERATIONS is used to set the expected number
   * of iterations for "testLoop". */
  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(functionLoop,
    MCUXCLCSSLFLOWPROTECTION_OK,
    MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK,
    MCUX_CSSL_FP_LOOP_ITERATIONS(testLoop, ITERATION_COUNT)
  );
}

/****************************************************************************/
/* Unprotected main example function                                        */
/****************************************************************************/

/* Since the program flow has already been verified in functionLoop,
 * via MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK, there is no token to be
 * checked here. By using MCUX_CSSL_FP_RESULT, we extract the return value
 * from an flow-protected function return value. */
MCUX_CSSL_EX_FUNCTION(mcuxCsslFlowProtection_Loop_example)
{
  uint32_t returnCode = MCUX_CSSL_FP_RESULT(uint32_t, functionLoop());
  if (MCUXCLCSSLFLOWPROTECTION_OK != returnCode)
  {
    return MCUX_CSSL_EX_ERROR;
  }
  return MCUX_CSSL_EX_OK;
}
