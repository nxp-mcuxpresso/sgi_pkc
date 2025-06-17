/*--------------------------------------------------------------------------*/
/* Copyright 2021-2024 NXP                                                  */
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

/** @file  mcuxClAeadModes_Sgi_Modes.c
 *  @brief Definition of the mode descriptors for all provided Cipher modes
 */

#include <mcuxClAeadModes_Modes.h>

#include <internal/mcuxClAead_Descriptor.h>
#include <internal/mcuxClAeadModes_Common_Functions.h>
#include <internal/mcuxClAeadModes_Sgi_Algorithms.h>
#include <internal/mcuxClAeadModes_Sgi_Types.h>

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClAead_ModeDescriptor_t mcuxClAead_ModeDescriptor_AES_GCM = {
  .encrypt = mcuxClAeadModes_encrypt,
  .protection_token_encrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_encrypt),
  .decrypt = mcuxClAeadModes_decrypt,
  .protection_token_decrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_decrypt),

  .init_enc = mcuxClAeadModes_init_encrypt,
  .protection_token_init_enc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_init_encrypt),
  .init_dec = mcuxClAeadModes_init_decrypt,
  .protection_token_init_dec = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_init_decrypt),
  .processAad = mcuxClAeadModes_process_adata,
  .protection_token_processAad = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_process_adata),
  .process = mcuxClAeadModes_process,
  .protection_token_process = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_process),
  .finish = mcuxClAeadModes_finish,
  .protection_token_finish = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_finish),
  .verify = mcuxClAeadModes_verify,
  .protection_token_verify = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_verify),
  .algorithm = &mcuxClAeadModes_AlgorithmDescriptor_Gcm
};

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClAead_ModeDescriptor_t mcuxClAead_ModeDescriptor_AES_CCM = {
  .encrypt = mcuxClAeadModes_encrypt,
  .protection_token_encrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_encrypt),
  .decrypt = mcuxClAeadModes_decrypt,
  .protection_token_decrypt = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_decrypt),

  .init_enc = mcuxClAeadModes_init_encrypt,
  .protection_token_init_enc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_init_encrypt),
  .init_dec = mcuxClAeadModes_init_decrypt,
  .protection_token_init_dec = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_init_decrypt),
  .processAad = mcuxClAeadModes_process_adata,
  .protection_token_processAad = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_process_adata),
  .process = mcuxClAeadModes_process,
  .protection_token_process = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_process),
  .finish = mcuxClAeadModes_finish,
  .protection_token_finish = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_finish),
  .verify = mcuxClAeadModes_verify,
  .protection_token_verify = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAeadModes_verify),
  .algorithm = &mcuxClAeadModes_AlgorithmDescriptor_Ccm
};
