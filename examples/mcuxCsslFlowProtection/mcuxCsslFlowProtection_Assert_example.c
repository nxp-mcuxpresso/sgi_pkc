/*--------------------------------------------------------------------------*/
/* Copyright 2020-2024 NXP                                                  */
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
 * @example mcuxCsslFlowProtection_Assert_example.c
 * @brief   Example for the Assert functionality of the Flow Protection component
 */

#define MCUX_CSSL_FP_ASSERT_CALLBACK() assertCallback()

#include <mcuxCsslExamples.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>

/* Example global SC */
static volatile uint32_t testVariable = 0u;

/****************************************************************************/
/* Function declaration                                                     */
/****************************************************************************/

void assertCallback(void);


/****************************************************************************/
/* Protected function declarations                                          */
/****************************************************************************/
MCUX_CSSL_FP_FUNCTION_DECL(functionOnly0Assert) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(void) functionOnly0Assert(void);

MCUX_CSSL_FP_FUNCTION_DECL(functionOnly1Assert) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionOnly1Assert(void);

MCUX_CSSL_FP_FUNCTION_DECL(functionAssert) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(void) functionAssert(void);


/****************************************************************************/
/* Function definitions                                                     */
/****************************************************************************/

void assertCallback(void)
{
  testVariable = 0xFFU;
}

/****************************************************************************/
/* Protected function definitions                                           */
/****************************************************************************/

/*
 * Example for a very basic protected function (without any protected code), used in the functionAssert example.
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionOnly0Assert) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(void) functionOnly0Assert(void)
{
  /* FUNCTION_ENTRY initializes the flow protection for this function. */
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionOnly0Assert);

  /* FUNCTION_EXIT encodes the result together with a protection token in the
   * return code. */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(functionOnly0Assert);
}

/* Another simple protected function, used in the functionAssert example. */
MCUX_CSSL_FP_FUNCTION_DEF(functionOnly1Assert)
MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) functionOnly1Assert(void)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionOnly1Assert);
  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(functionOnly1Assert, 1u, 0xFAFAu);
}

/*
 * Example of a protected function that performs an assertion.
 */
MCUX_CSSL_FP_FUNCTION_DEF(functionAssert) /* Important: no semicolon here! */
MCUX_CSSL_FP_PROTECTED_TYPE(void) functionAssert(void)
{
  /* The protected function that will be called must be declared as expected,
   * either in the FUNCTION_ENTRY, FUNCTION_EXIT, EXPECT, or an event that
   * accepts expectation declarations.
   * FUNCTION_ENTRY can be used with and without providing expectations. */
  MCUX_CSSL_FP_FUNCTION_ENTRY(functionAssert,
    MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly0Assert)
  );

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(functionOnly0Assert());

  /* The ASSERT macro allows the currently recorded code flow to be checked.
   * The call to functionOnly has already been recorded as expected at the
   * function entry, so at this point the only remaining expectation is that
   * the function has been entered. */
  MCUX_CSSL_FP_ASSERT(
    MCUX_CSSL_FP_FUNCTION_ENTERED(functionAssert)
  );

  (void) functionOnly1Assert();

  /* At this point the functionOnly1Assert call event should have happened, but not
   * yet recorded as an expectation. Therefore it should be specified as an
   * expected event for the assertion to pass. */
  MCUX_CSSL_FP_ASSERT(
    MCUX_CSSL_FP_FUNCTION_ENTERED(functionAssert),
    MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly1Assert)
  );

  /* This assertion will fail since it misses the expectation for the
   * functionOnly1Assert call event. */
  MCUX_CSSL_FP_ASSERT(
    MCUX_CSSL_FP_FUNCTION_ENTERED(functionAssert)
  );

  /* At this point MCUX_CSSL_FP_ASSERT_CALLBACK should be already executed
  testVariable should be set to 0xFF*/

  /* FUNCTION_EXIT can be used with and without providing expectations. */
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(functionAssert,
    MCUX_CSSL_FP_FUNCTION_CALLED(functionOnly1Assert)
  );
}

/****************************************************************************/
/* Unprotected main example function                                        */
/****************************************************************************/

MCUX_CSSL_EX_FUNCTION(mcuxCsslFlowProtection_Assert_example)
{
  /* Return value from FP token is not used */
  (void) functionAssert();

  return MCUX_CSSL_EX_OK;
}
