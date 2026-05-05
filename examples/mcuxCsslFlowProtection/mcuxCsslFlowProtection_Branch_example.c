/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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
 * @example mcuxCsslFlowProtection_Branch_example.c
 * @brief   Example for the Branch functionality of the Flow Protection component
 */

#include <mcuxCsslExamples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>

/****************************************************************************/
/* Defines                                                                  */
/****************************************************************************/

#define MCUXCLCSSLFLOWPROTECTION_OK            0x2EDEu
#define MCUXCLCSSLFLOWPROTECTION_NOT_OK        0x89ADu
#define MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK  0xF0FAu

/****************************************************************************/
/* Protected function declarations                                          */
/****************************************************************************/

MCUX_CSSL_FP_FUNCTION_DECL(functionBranch) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionBranch(uint32_t arg);

MCUX_CSSL_FP_FUNCTION_DECL(functionBranch1) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionBranch1(uint32_t arg);

MCUX_CSSL_FP_FUNCTION_DECL(functionSwitch) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionSwitch(uint32_t arg);

/****************************************************************************/
/* Protected function definitions                                           */
/****************************************************************************/

/*
 * Example of a protected function that performs a protected branch.
 *
 * Note that the else case cannot be omitted, even if it would be empty except
 * for the BRANCH macro.
 * Also, both MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE and MCUX_CSSL_FP_BRANCH_TAKEN_NEGATIVE
 * need to be present for every protected branch.
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionBranch) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionBranch(uint32_t arg)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionBranch);

  /* Every protected entity needs to be declared, hence also this branch. */
  MCUX_CSSL_FP_BRANCH_DECL(argCheck);
  uint32_t result;
  if (MCUXCLCSSLFLOWPROTECTION_OK == arg)
  {
    result = MCUXCLCSSLFLOWPROTECTION_OK;

    /* Within the positive scenario of a protected branch, a BRANCH_POSITIVE
     * event must be placed, to indicate to the flow protection mechanism that
     * the positive scenario of the protected branch has been executed. */
    MCUX_CSSL_FP_BRANCH_POSITIVE(argCheck);
  }
  else
  {
    result = MCUXCLCSSLFLOWPROTECTION_NOT_OK;

    /* Within the negative scenario of a protected branch, a BRANCH_NEGATIVE
     * event must be placed, to indicate to the flow protection mechanism that
     * the negative scenario of the protected branch has been executed. */
    MCUX_CSSL_FP_BRANCH_NEGATIVE(argCheck);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(functionBranch, result, MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK,
    /* Option 1: provide the condition as part of the branch expectation. */
    MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(argCheck, MCUXCLCSSLFLOWPROTECTION_OK == arg),
    /* Option 2: place the branch expectation in a conditional block. */
    MCUX_CSSL_FP_CONDITIONAL(MCUXCLCSSLFLOWPROTECTION_OK != arg,
      MCUX_CSSL_FP_BRANCH_TAKEN_NEGATIVE(argCheck)
    )
  );
}

/*
 * Annother example of a protected function that performs a protected branch.
 *
 * This time we exit the function inside the if branch.
 * This allows to check MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE only in the if branch
 * and MCUX_CSSL_FP_BRANCH_TAKEN_NEGATIVE only at the end of the function.
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionBranch1) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionBranch1(uint32_t arg)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionBranch1);

  MCUX_CSSL_FP_BRANCH_DECL(argCheck);
  uint32_t result;
  if (MCUXCLCSSLFLOWPROTECTION_OK == arg)
  {
    MCUX_CSSL_FP_BRANCH_POSITIVE(argCheck);
    result = MCUXCLCSSLFLOWPROTECTION_OK;

    /* Since we exit from within the if branch, we do not need to include
     * a condition for MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE. We also do not need to
     * includde MCUX_CSSL_FP_BRANCH_TAKEN_NEGATIVE here. */
    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(functionBranch1, result, MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK,
      MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(argCheck));
  }
  else
  {
    result = MCUXCLCSSLFLOWPROTECTION_NOT_OK;
    MCUX_CSSL_FP_BRANCH_NEGATIVE(argCheck);
  }

  /* We expect that the else case has been executed, so we use
   * MCUX_CSSL_FP_BRANCH_TAKEN_NEGATIVE without condition. */
  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(functionBranch1, result, MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK,
    MCUX_CSSL_FP_BRANCH_TAKEN_NEGATIVE(argCheck));
}

/*
 * Example of a protected function that performs a protected switch.
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionSwitch) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionSwitch(uint32_t arg)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionSwitch);

  /* Every protected entity needs to be declared, hence also this switch. */
  MCUX_CSSL_FP_SWITCH_DECL(argSwitch);
  uint32_t result;
  switch (arg)
  {
    case MCUXCLCSSLFLOWPROTECTION_OK:
    {
      result = MCUXCLCSSLFLOWPROTECTION_OK;

      /* Within a case of a protected switch, a SWITCH_CASE event must be
       * placed, to indicate to the flow protection mechanism that this
       * particular case has been executed. */
      MCUX_CSSL_FP_SWITCH_CASE(argSwitch, MCUXCLCSSLFLOWPROTECTION_OK);
      break;
    }
    case MCUXCLCSSLFLOWPROTECTION_NOT_OK:
    {
      result = MCUXCLCSSLFLOWPROTECTION_NOT_OK;

      /* Within a case of a protected switch, a SWITCH_CASE event must be
       * placed, to indicate to the flow protection mechanism that this
       * particular case has been executed. */
      MCUX_CSSL_FP_SWITCH_CASE(argSwitch, MCUXCLCSSLFLOWPROTECTION_NOT_OK);
      break;
    }
    default:
    {
      result = 0;

      /* Within the default case of a protected switch, a SWITCH_DEFAULT event
       * must be placed, to indicate to the flow protection mechanism that the
       * default case has been executed. */
      MCUX_CSSL_FP_SWITCH_DEFAULT(argSwitch);
      break;
    }
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(functionSwitch, result,
    /* Option 1: provide the condition as part of the switch expectation. */
    MCUX_CSSL_FP_SWITCH_TAKEN(argSwitch, MCUXCLCSSLFLOWPROTECTION_OK, MCUXCLCSSLFLOWPROTECTION_OK == arg),
    MCUX_CSSL_FP_SWITCH_TAKEN(argSwitch, MCUXCLCSSLFLOWPROTECTION_NOT_OK, MCUXCLCSSLFLOWPROTECTION_NOT_OK == arg),
    /* Option 2: place the switch expectation in a conditional block. */
    MCUX_CSSL_FP_CONDITIONAL((MCUXCLCSSLFLOWPROTECTION_OK != arg) && (MCUXCLCSSLFLOWPROTECTION_NOT_OK != arg),
      MCUX_CSSL_FP_SWITCH_TAKEN_DEFAULT(argSwitch)
    )
  );
}

/****************************************************************************/
/* Unprotected main example function                                        */
/****************************************************************************/

MCUX_CSSL_EX_FUNCTION(mcuxCsslFlowProtection_Branch_example)
{

  MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(returnCode, token0, functionBranch(MCUXCLCSSLFLOWPROTECTION_OK));

  if (MCUXCLCSSLFLOWPROTECTION_OK != returnCode)
  {
    return MCUX_CSSL_EX_ERROR;
  }

#if !defined(MCUX_CSSL_FP_USE_CODE_SIGNATURE) && !defined(MCUX_CSSL_FP_USE_NONE)
  if (!(MCUX_CSSL_FP_FUNCTION_CALLED(functionBranch) == token0))
  {
    return MCUX_CSSL_EX_ERROR;
  }
#else
  (void) token0;
#endif

  MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(returnCode1, token1, functionBranch1(MCUXCLCSSLFLOWPROTECTION_OK));

  if (MCUXCLCSSLFLOWPROTECTION_OK != returnCode1)
  {
    return MCUX_CSSL_EX_ERROR;
  }

#if !defined(MCUX_CSSL_FP_USE_CODE_SIGNATURE) && !defined(MCUX_CSSL_FP_USE_NONE)
  if (!(MCUX_CSSL_FP_FUNCTION_CALLED(functionBranch1) == token1))
  {
    return MCUX_CSSL_EX_ERROR;
  }
#else
  (void) token1;
#endif

  MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(returnCode2, token2, functionSwitch(MCUXCLCSSLFLOWPROTECTION_OK));

  if (MCUXCLCSSLFLOWPROTECTION_OK != returnCode2)
  {
    return MCUX_CSSL_EX_ERROR;
  }

#if !defined(MCUX_CSSL_FP_USE_CODE_SIGNATURE) && !defined(MCUX_CSSL_FP_USE_NONE)
  if (!(MCUX_CSSL_FP_FUNCTION_CALLED(functionSwitch) == token2))
  {
    return MCUX_CSSL_EX_ERROR;
  }
#else
  (void) token2;
#endif

  return MCUX_CSSL_EX_OK;
}
