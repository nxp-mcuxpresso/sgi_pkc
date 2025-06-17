/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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

/** @file  mcuxClAead.c
 *  @brief Implementation of the multipart and one shot functions of the mcuxClAead component */

#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClAead.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>

#include <internal/mcuxClAead_Ctx.h>
#include <internal/mcuxClAead_Descriptor.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_decrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_decrypt(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength,
  mcuxCl_InputBuffer_t pTag,
  uint32_t tagLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClAead_decrypt, diRefValue, MCUXCLAEAD_STATUS_FAULT_ATTACK);

  *pOutLength = 0u;
  MCUX_CSSL_FP_FUNCTION_CALL(status, mode->decrypt(
    /* mcuxClSession_Handle_t session,        */ session,
    /* mcuxClKey_Handle_t key,                */ key,
    /* mcuxClAead_Mode_t mode,                */ mode,
    /* mcuxCl_InputBuffer_t pNonce,           */ pNonce,
    /* uint32_t nonceLength,                 */ nonceLength,
    /* mcuxCl_InputBuffer_t pIn,              */ pIn,
    /* uint32_t inLength,                    */ inLength,
    /* mcuxCl_InputBuffer_t pAdata,           */ pAdata,
    /* uint32_t adataLength,                 */ adataLength,
    /* mcuxCl_InputBuffer_t pTag,             */ pTag,
    /* uint32_t  taglength,                  */ tagLength,
    /* mcuxCl_Buffer_t pOut,                  */ pOut,
    /* uint32_t * const pOutlength           */ pOutLength
  ));

  MCUXCLSESSION_EXIT(session,
                    mcuxClAead_decrypt,
                    diRefValue,
                    status,
                    MCUXCLAEAD_STATUS_FAULT_ATTACK,
                    mode->protection_token_decrypt);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_encrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_encrypt(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength,
  mcuxCl_Buffer_t pTag,
  uint32_t tagLength
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClAead_encrypt, diRefValue, MCUXCLAEAD_STATUS_FAULT_ATTACK);

  *pOutLength = 0u;
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->encrypt(
    /* mcuxClSession_Handle_t session,        */ session,
    /* mcuxClKey_Handle_t key,                */ key,
    /* mcuxClAead_Mode_t mode,                */ mode,
    /* mcuxCl_InputBuffer_t pNonce,           */ pNonce,
    /* uint32_t nonceLength,                 */ nonceLength,
    /* mcuxCl_InputBuffer_t pIn,              */ pIn,
    /* uint32_t inLength,                    */ inLength,
    /* mcuxCl_InputBuffer_t pAdata,           */ pAdata,
    /* uint32_t adataLength,                 */ adataLength,
    /* mcuxCl_Buffer_t pOut,                  */ pOut,
    /* uint32_t * const pOutLength,          */ pOutLength,
    /* mcuxCl_Buffer_t pTag,                  */ pTag,
    /* uint32_t tagLength,                   */ tagLength
  ));

  MCUXCLSESSION_EXIT(session,
                    mcuxClAead_encrypt,
                    diRefValue,
                    MCUXCLAEAD_STATUS_OK,
                    MCUXCLAEAD_STATUS_FAULT_ATTACK,
                    mode->protection_token_encrypt);
}





MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_init_encrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_init_encrypt(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint32_t inLength,
  uint32_t adataLength,
  uint32_t tagLength
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClAead_init_encrypt, diRefValue, MCUXCLAEAD_STATUS_FAULT_ATTACK);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->init_enc(
    /* mcuxClSession_Handle_t session,        */ session,
    /* mcuxClAead_Context_t * const pContext, */ pContext,
    /* mcuxClKey_Handle_t key,                */ key,
    /* mcuxClAead_Mode_t mode,                */ mode,
    /* mcuxCl_InputBuffer_t pNonce,           */ pNonce,
    /* uint32_t nonceLength,                 */ nonceLength,
    /* uint32_t inLength,                    */ inLength,
    /* uint32_t adataLength,                 */ adataLength,
    /* uint32_t tagLength,                   */ tagLength
  ));

  MCUXCLSESSION_EXIT(session,
                    mcuxClAead_init_encrypt,
                    diRefValue,
                    MCUXCLAEAD_STATUS_OK,
                    MCUXCLAEAD_STATUS_FAULT_ATTACK,
                    mode->protection_token_init_enc);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_init_decrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_init_decrypt(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxClKey_Handle_t key,
  mcuxClAead_Mode_t mode,
  mcuxCl_InputBuffer_t pNonce,
  uint32_t nonceLength,
  uint32_t inLength,
  uint32_t adataLength,
  uint32_t tagLength
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClAead_init_decrypt, diRefValue, MCUXCLAEAD_STATUS_FAULT_ATTACK);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mode->init_dec(
    /* mcuxClSession_Handle_t session,        */ session,
    /* mcuxClAead_Context_t * const pContext, */ pContext,
    /* mcuxClKey_Handle_t key,                */ key,
    /* mcuxClAead_Mode_t mode,                */ mode,
    /* mcuxCl_InputBuffer_t pNonce,           */ pNonce,
    /* uint32_t noncelength,                 */ nonceLength,
    /* uint32_t inlength,                    */ inLength,
    /* uint32_t adatalength,                 */ adataLength,
    /* uint32_t taglength,                   */ tagLength
  ));

  MCUXCLSESSION_EXIT(session,
                    mcuxClAead_init_decrypt,
                    diRefValue,
                    MCUXCLAEAD_STATUS_OK,
                    MCUXCLAEAD_STATUS_FAULT_ATTACK,
                    mode->protection_token_init_dec);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_process)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_process(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUXCLSESSION_ENTRY(session,
                      mcuxClAead_process,
                      diRefValue,
                      MCUXCLAEAD_STATUS_FAULT_ATTACK,
                      pContext->mode->protection_token_process);

  *pOutLength = 0u;
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pContext->mode->process(
    /* mcuxClSession_Handle_t session,        */ session,
    /* mcuxClAead_Context_t * const pContext, */ pContext,
    /* mcuxCl_InputBuffer_t pIn,              */ pIn,
    /* uint32_t inLength,                    */ inLength,
    /* mcuxCl_Buffer_t pOut,                  */ pOut,
    /* uint32_t * const pOutLength,          */ pOutLength
  ));

  MCUXCLSESSION_EXIT(session, mcuxClAead_process, diRefValue, MCUXCLAEAD_STATUS_OK, MCUXCLAEAD_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_process_adata)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_process_adata(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pAdata,
  uint32_t adataLength
)
{
  MCUXCLSESSION_ENTRY(session,
                      mcuxClAead_process_adata,
                      diRefValue,
                      MCUXCLAEAD_STATUS_FAULT_ATTACK,
                      pContext->mode->protection_token_processAad);

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pContext->mode->processAad(
    /* mcuxClSession_Handle_t session,        */ session,
    /* mcuxClAead_Context_t * const pContext, */ pContext,
    /* mcuxCl_InputBuffer_t pAdata,           */ pAdata,
    /* uint32_t adataLength,                 */ adataLength
  ));

  MCUXCLSESSION_EXIT(session, mcuxClAead_process_adata, diRefValue, MCUXCLAEAD_STATUS_OK, MCUXCLAEAD_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_finish)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t)  mcuxClAead_finish(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength,
  mcuxCl_Buffer_t pTag
)
{
  MCUXCLSESSION_ENTRY(session,
                      mcuxClAead_finish,
                      diRefValue,
                      MCUXCLAEAD_STATUS_FAULT_ATTACK,
                      pContext->mode->protection_token_finish);

  *pOutLength = 0u;
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(pContext->mode->finish(
    /* mcuxClSession_Handle_t session,        */ session,
    /* mcuxClAead_Context_t * const pContext, */ pContext,
    /* mcuxCl_Buffer_t pOut,                  */ pOut,
    /* uint32_t * const pOutLength,          */ pOutLength,
    /* mcuxCl_Buffer_t pTag,                  */ pTag
  ));

  MCUXCLSESSION_EXIT(session, mcuxClAead_finish, diRefValue, MCUXCLAEAD_STATUS_OK, MCUXCLAEAD_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_verify)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAead_verify(
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pTag,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength
)
{
  MCUXCLSESSION_ENTRY(session,
                      mcuxClAead_verify,
                      diRefValue,
                      MCUXCLAEAD_STATUS_FAULT_ATTACK,
                      pContext->mode->protection_token_verify);

  *pOutLength = 0u;
  MCUX_CSSL_FP_FUNCTION_CALL(status, pContext->mode->verify(
    /* mcuxClSession_Handle_t session,        */ session,
    /* mcuxClAead_Context_t * const pContext, */ pContext,
    /* mcuxCl_InputBuffer_t pTag,             */ pTag,
    /* mcuxCl_Buffer_t pOut,                  */ pOut,
    /* uint32_t * const pOutLength,          */ pOutLength
  ));

  MCUXCLSESSION_EXIT(session, mcuxClAead_verify, diRefValue, status, MCUXCLAEAD_STATUS_FAULT_ATTACK);
}

