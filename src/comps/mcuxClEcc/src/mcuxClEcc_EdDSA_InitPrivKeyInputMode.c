/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @file  mcuxClEcc_EdDSA_GenerateKeyPair.c
 * @brief implementation of TwEd_EdDsaKeyGen function
 */


#include <stdint.h>

#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClEcc.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_InitPrivKeyInputMode)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_EdDSA_InitPrivKeyInputMode(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_GenerationDescriptor_t *generationMode,
    const uint8_t *pPrivKey)
{
   MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_InitPrivKeyInputMode);
   (void) pSession;

  /* The struct EdDSA_GenerateKeyPairDescriptor needs to be initialized as well, as it contains the private key information together with the required option flag.
   * This struct will be put in memory directly after the struct Key_GenerationDescriptor.
   * The customer will provide enough memory for both structures by using MCUXCLECC_EDDSA_GENERATEKEYPAIR_DESCRIPTOR_SIZE to allocate the buffer for the output-param of this function.
   */
   MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Reinterpret structure for mode type, change uint8_t * to mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *")
   mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *mode = (mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *) ((uint8_t *)generationMode + sizeof(mcuxClKey_GenerationDescriptor_t));
   MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
   MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer mode has compatible type and cast was valid")
   mode->options = MCUXCLECC_EDDSA_PRIVKEY_INPUT;
   mode->pPrivKeyInput = pPrivKey;
   MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
   generationMode->pKeyGenFct = mcuxClEcc_EdDSA_GenerateKeyPair;
   generationMode->protectionTokenKeyGenFct = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateKeyPair);
   generationMode->pProtocolDescriptor = (const void *) mode;

   MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(
     mcuxClEcc_EdDSA_InitPrivKeyInputMode,
     MCUXCLECC_STATUS_OK,
     MCUXCLECC_STATUS_FAULT_ATTACK
   );
}

