/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

#include <internal/mcuxClDma_Resource.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_requestInputAndOutput)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_requestInputAndOutput(
  mcuxClSession_Handle_t session,
  mcuxClSession_HwInterruptHandler_t callbackFunction,
  uint32_t protectionToken_callbackFunction
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClDma_requestInputAndOutput);

  mcuxClSession_Channel_t inChannel = mcuxClSession_getDmaInputChannel(session);
  mcuxClSession_Channel_t outChannel = mcuxClSession_getDmaOutputChannel(session);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_request(session, inChannel, callbackFunction, protectionToken_callbackFunction));

  /* User might use the same channel for input and output. Only request output if they differ. */
  if(inChannel != outChannel)
  {
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_request(session, outChannel, callbackFunction, protectionToken_callbackFunction));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClDma_requestInputAndOutput,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_request),
    MCUX_CSSL_FP_CONDITIONAL((inChannel != outChannel), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_request)));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClDma_releaseInputAndOutput)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClDma_releaseInputAndOutput(
  mcuxClSession_Handle_t session
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClDma_releaseInputAndOutput);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_release(session, mcuxClSession_getDmaInputChannel(session)));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClDma_release(session, mcuxClSession_getDmaOutputChannel(session)));
  /* Delayed check for errors to achieve the cleanest state possible. If input and output channels are identical, the second release call shall have no effect. */

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClDma_releaseInputAndOutput,
    2U * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClDma_release)
  );
}

