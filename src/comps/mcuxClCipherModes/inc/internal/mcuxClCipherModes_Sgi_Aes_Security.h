/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

#ifndef MCUXCLCIPHERMODES_SGI_AES_SECURITY_H_
#define MCUXCLCIPHERMODES_SGI_AES_SECURITY_H_

#include <mcuxClCore_Platform.h>

#include <mcuxClBuffer.h>
#include <mcuxClKey_Types.h>
#include <mcuxClSession.h>

#include <internal/mcuxClCipherModes_Sgi_Types.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>


/**
 * @brief Function used for DFA protection.
 *
 * This function is capable of computing en/decryption multiple times (depends on security setting
 * and feature SESSION_SECURITYOPTIONS_ADDITIONAL_SWCOMP) and comparing CRC result
 * of each calculation with each other to determine if any fault was injected in between calculations
 *
 * This function fulfills SREQI_BCIPHER_11
 * Code flow is described in detail in SREQI_BCIPHER_11
 *
 * @param      session      Handle for the current CL session.
 * @param      pContext     Pointer to multipart context
 * @param[in]  pWa          Pointer to cpu workarea
 * @param[in]  pIn          Buffer which holds the input data
 * @param[in]  pOut         Buffer to hold the output data
 * @param[in]  inLength     Length of input data
 * @param[in]  pIvOut       Pointer for the updated Iv
 * @param[in]  pOutLength   Pointer to length of output data
 * @param[in]  pKeyChecksum Pointer to mcuxClKey_KeyChecksum_t
 * @param[in]  cryptEngine  Engine function to do the specified crypt operation
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_crypt)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_crypt(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_Context_Aes_Sgi_t* pContext,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  uint32_t inLength,
  uint32_t* pIvOut,
  uint32_t* const pOutLength,
  mcuxClKey_KeyChecksum_t* pKeyChecksum,
  mcuxClCipherModes_EngineFunc_AesSgi_t cryptEngine,
  uint32_t protectionToken_cryptEngine
);

#endif /* MCUXCLCIPHERMODES_SGI_AES_SECURITY_H_ */
