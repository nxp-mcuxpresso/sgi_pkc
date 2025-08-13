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
 * @example mcuxCsslFlowProtection_Function_example.c
 * @brief   Example for the Function functionality of the Flow Protection component
 */

#include <mcuxCsslExamples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>

/* Protected function pointer type */
MCUX_CSSL_FP_FUNCTION_POINTER(functionPointerType_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) (*functionPointerType_t)(void));

/****************************************************************************/
/* Defines                                                                  */
/****************************************************************************/

#define MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY   0xC0DEu
#define MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY1  0x2EDEu
#define MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY2  0x0002u
#define MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK        0xF0FAu

/****************************************************************************/
/* Function declaration                                                     */
/****************************************************************************/

uint32_t functionOnly(void);

/****************************************************************************/
/* Protected function declarations                                          */
/****************************************************************************/

MCUX_CSSL_FP_FUNCTION_DECL(functionOnly0) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(void) functionOnly0(void);

MCUX_CSSL_FP_FUNCTION_DECL(functionOnly1) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionOnly1(void);

MCUX_CSSL_FP_FUNCTION_DECL(functionOnly2, functionPointerType_t) /* Important: no semicolon here & adding functionPointerType info! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionOnly2(void);

MCUX_CSSL_FP_FUNCTION_DECL(functionCall) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(void) functionCall(void);

MCUX_CSSL_FP_FUNCTION_DECL(functionCalls) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionCalls(void);

/****************************************************************************/
/* Function definitions                                                     */
/****************************************************************************/

uint32_t functionOnly(void)
{
  return MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY;
}

/****************************************************************************/
/* Protected function definitions                                           */
/****************************************************************************/

/*
 * Example for a very basic protected function (without any protected code).
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionOnly0) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(void) functionOnly0(void)
{
  /* FUNCTION_ENTRY initializes the flow protection for this function. */
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionOnly0);

  /* FUNCTION_EXIT encodes the result together with a protection token in the
   * return code. */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(functionOnly0);
}

/* Another simple protected function, used in functionCalls example. */
MCUX_CSSL_FP_FUNCTION_DEF(functionOnly1)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionOnly1(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionOnly1);
  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(functionOnly1, MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY1, MCUXCLCSSLFLOWPROTECTION_FAULT_ATTACK);
}

/* Another simple protected function, used in functionCalls example. */
MCUX_CSSL_FP_FUNCTION_DEF(functionOnly2, functionPointerType_t)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionOnly2(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionOnly2);
  MCUX_CSSL_FP_FUNCTION_EXIT(functionOnly2, MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY2);
}

/*
 * Example of a protected function that performs a protected function call.
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionCall) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(void) functionCall(void)
{
  /* The protected function that will be called must be declared as expected,
   * either in the FUNCTION_ENTRY, FUNCTION_EXIT, EXPECT, or an event that
   * accepts expectation declarations.
   * FUNCTION_ENTRY can be used with and without providing expectations. */
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionCall,
  	MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly0)
  );

  /* A call to a protected function must be wrapped using FUNCTION_CALL. This
   * is needed to capture and process the protection token, returned by the
   * function that is called, and inform the flow protection mechanism of this
   * function call event. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(functionOnly0());

  /* FUNCTION_EXIT can be used with and without providing expectations. */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(functionCall);
}

/*
 * Example of a protected function that performs multiple function calls.
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionCalls) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionCalls(void)
{
  /* FUNCTION_ENTRY can be used with multiple expectations. */
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionCalls,
  	MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly0),
  	MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly1)
  );

  /* Multiple calls to protected functions.
   * Note: the provided result variables must be unique. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(functionOnly0());
  MCUX_CSSL_FP_FUNCTION_CALL(result1, functionOnly1());
  MCUX_CSSL_FP_FUNCTION_CALL(result2, functionOnly2());

  /* EXPECT can be used to provide expectations in the body of the function.
   * Note: using it with a single expectation is considered unsecure. */
  MCUX_CSSL_FP_EXPECT(
    MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly0)
  );

  /* It is still possible to call unprotected functions. */
  uint32_t result = functionOnly();

  /* Another block of protected function calls.
   * Note: the provided result variables must be unique. */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(functionOnly0());
  MCUX_CSSL_FP_FUNCTION_CALL(result1_, functionOnly1());
  MCUX_CSSL_FP_FUNCTION_CALL(result2_, functionOnly2());

  /* EXPECT can also be used with multiple expectations. */
  MCUX_CSSL_FP_EXPECT(
    MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly0),
    MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly2)
  );

  /* Another protected function call */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(functionOnly0());

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Calculation does not overflow")
  result += result1 + result2 + result1_ + result2_;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
  /* FUNCTION_EXIT can also be used with multiple expectations. */
  MCUX_CSSL_FP_FUNCTION_EXIT(functionCalls, result,
  	MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly1),
  	MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly2)
  );

  /* In this function we have had various calls, i.e. call events:
   *  - functionOnly0 (3 times)
   *  - functionOnly1 (2 times)
   *  - functionOnly2 (2 times)
   *  - functionOnly (unprotected, so not considered as a protected event)
   *
   * Every one of these events needs to be declared as expected for the flow
   * protection mechanism to be able operate properly, in this example:
   *  - functionOnly0, in FUNCTION_ENTRY and twice in EXPECT
   *  - functionOnly1, in FUNCTION_ENTRY and FUNCTION_EXIT
   *  - functionOnly2, in FUNCTION_EXIT and EXPECT
   *  - functionOnly, no need to declare, since unprotected.
   */
}

/****************************************************************************/
/* Unprotected main example function                                        */
/****************************************************************************/

/* This main function of this example collection is not flow protected.
 *
 * We use MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED and MCUX_CSSL_FP_FUNCTION_CALL_VOID_PROTECTED
 * to call protected functions from within unprotected functions.
 * As for protected functions, we use MCUX_CSSL_FP_FUNCTION_CALLED to balance the protected function call.
 * (See e.g. functionCalls() call).
 *
 * An alternative for MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED would be MCUX_CSSL_FP_FUNCTION_CALL_BEGIN
 * and MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN together with MCUX_CSSL_FP_FUNCTION_CALL_END and
 * MCUX_CSSL_FP_FUNCTION_CALL_VOID_END respectively. Here, MCUX_CSSL_FP_FUNCTION_CALLED must be used
 * between _BEGIN and _END macros. (See functionOnly2() call).
 */
MCUX_CSSL_EX_FUNCTION(mcuxCsslFlowProtection_Function_example)
{

  /* Unprotected function is called directly */
  const uint32_t rOnly = functionOnly();
  (void) rOnly;

  /* Return value from FP token is not used */
  (void) functionCall();

  /* Protected function is called from unprotected function (Method 1) */
  MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(returnCode, token, functionCalls());

  const uint32_t expectedReturnCode = MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY
                                    + MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY1
                                    + MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY2
                                    + MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY1
                                    + MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY2;
  if (expectedReturnCode != returnCode)
  {
    return MCUX_CSSL_EX_ERROR;
  }

#if !defined(MCUX_CSSL_FP_USE_CODE_SIGNATURE) && !defined(MCUX_CSSL_FP_USE_NONE)
  if (MCUX_CSSL_FP_FUNCTION_CALLED(functionCalls) != token)
  {
    return MCUX_CSSL_EX_ERROR;
  }
#else
  (void) token;
#endif

  functionPointerType_t funcPtr = functionOnly2;

  /* Protected function is called from unprotected function (Method 2) */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(returnCode1, token1, funcPtr());

  if (MCUXCLCSSLFLOWPROTECTION_RET_FUNCTION_ONLY2 != returnCode1)
  {
    return MCUX_CSSL_EX_ERROR;
  }

#if !defined(MCUX_CSSL_FP_USE_CODE_SIGNATURE) && !defined(MCUX_CSSL_FP_USE_NONE)
  const uint32_t funcPtrToken = MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly2);
  if (!(funcPtrToken == token1))
  {
    return MCUX_CSSL_EX_ERROR;
  }
#else
  (void) token1;
#endif

  MCUX_CSSL_FP_FUNCTION_CALL_END();

  return MCUX_CSSL_EX_OK;
}
