/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/**
 * @file  mcuxClKdfModes_Internal_Algorithms.h
 * @brief Declarations and definitions for the KDF
 */

#ifndef MCUXCLKDFMODES_INTERNAL_ALGORITHMS_H_
#define MCUXCLKDFMODES_INTERNAL_ALGORITHMS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSession.h>
#include <mcuxClKey_Types.h>
#include <internal/mcuxClMac_Internal_Constants.h>
#include <internal/mcuxClHashModes_Internal_Memory.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mcuxClKdfModes_WorkArea {
  uint8_t input_Wa[8u];
  uint32_t context_Wa[MCUXCLMAC_MAX_CONTEXT_SIZE_IN_WORDS];
  uint8_t macResult_Wa[MCUXCLCORE_MAX(MCUXCLMAC_MAX_OUTPUT_SIZE, MCUXCLHASH_BLOCK_SIZE_MAX_WITHOUT_MASK)];
} mcuxClKdfModes_WorkArea_t;

/**
 * @brief Key derivation engine function for NIST SP800-108.
 *
 * @param[in]     pSession          Session handle.
 * @param         derivationMode    Derivation mode, can be created with corresponding ModeConstructor.
 * @param[in]     derivationKey     Input derivation key (word-aligned).
 * @param         inputs            The first element contains the label, the second contains the context and the third contains IV (only for Feedback mode).
 * @param         numberOfInputs    Fixed to 3 for Feedback mode and 2 for other modes.
 * @param[out]    derivedKey        Output key handle (word-aligned).
 *
 * @return mcuxClKey_Status_t
 * @retval MCUXCLKEY_STATUS_OK              If the key derivation was succesful.
 * @retval MCUXCLKEY_STATUS_INVALID_INPUT
 * @retval MCUXCLKEY_STATUS_ERROR           If the key derivation was not succesful.
 * @retval MCUXCLKEY_STATUS_INVALID_INPUT
 * @retval MCUXCLKEY_STATUS_FAULT_ATTACK    In case of a fault attack
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_derivationEngine_NIST_SP800_108, mcuxClKey_DerivationEngine_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_derivationEngine_NIST_SP800_108(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Derivation_t derivationMode,
    mcuxClKey_Handle_t derivationKey,
    mcuxClKey_DerivationInput_t inputs[],
    uint32_t numberOfInputs,
    mcuxClKey_Handle_t derivedKey
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLKDFMODES_INTERNAL_ALGORITHMS_H_ */
