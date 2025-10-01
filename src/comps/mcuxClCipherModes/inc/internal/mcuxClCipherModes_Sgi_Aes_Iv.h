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

#ifndef MCUXCLCIPHERMODES_SGI_AES_IV_H_
#define MCUXCLCIPHERMODES_SGI_AES_IV_H_

#include <mcuxClSession_Types.h>
#include <internal/mcuxClCipherModes_Common_Wa.h>
#include <mcuxClSgi_Types.h>
#include <mcuxClDma_Types.h>

/**
 * @brief Function used to load IV
 *
 * @param[in]     session     Handle for the current CL session.
 * @param[in,out] pWa         pointer to workarea used in cipher mode.
 * @param[in,out] pIv         pointer to buffer of IV.
 *
 * @post
 *  - pWa->pIV and pWa->ctrSize will be updated.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_IV, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv
);

/**
 * @brief Function sets pointer to inital vector to NULL for modes where it is not needed.
 *
 * @param[in]     session     Handle for the current CL session.
 * @param[in,out] pWa         pointer to workarea used in cipher mode.
 * @param[in]     pIv         pointer to buffer of IV, it is UNUSED.
 *
 * @post
 *  - pWa->pIV is set to NULL
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_No_IV, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_No_IV(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t* pWa,
  mcuxCl_InputBuffer_t pIv
);

/**
 * @brief Function copies IV to SGI DATIN0.
 *
 * @param[in]     session     Handle for the current CL session.
 * @param[in,out] pWa         pointer to workarea used in cipher mode.
 * @param[in]     pIv         pointer to buffer of IV.
 * 
 * @post
 *   - pWa->pIV will be updated.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_IV_AutoMode_Ctr, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_AutoMode_Ctr(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv
);

/**
 * @brief Function copies IV to SGI DATOUT.
 *
 * @param[in]     session     Handle for the current CL session.
 * @param[in,out] pWa         pointer to workarea used in cipher mode.
 * @param[in]     pIv         pointer to buffer of IV.
 *
 * @post
 *   - pWa->pIV will be updated.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_IV_to_DATOUT_DMA, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_to_DATOUT_DMA(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv
);

/**
 * @brief Function copies IV to SGI DATIN2.
 *
 * @param[in]     session     Handle for the current CL session.
 * @param[in,out] pWa         pointer to workarea used in cipher mode.
 * @param[in]     pIv         pointer to buffer of IV.
 *
 * @post
 *   - pWa->pIV will be updated.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_IV_AutoMode_Cbc_Dec, mcuxClCipherModes_SetupIvFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_IV_AutoMode_Cbc_Dec(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_WorkArea_t *pWa,
  mcuxCl_InputBuffer_t pIv
);

/**
 * @brief Function checks length of the IV for modes where inital vector is not needed.
 *
 * @param[in] ivLength          Length of the IV
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_checkIvLen_noIv, mcuxClCipherModes_CheckIvLength_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_checkIvLen_noIv(
  mcuxClSession_Handle_t session,
  uint32_t ivLength);

/**
 * @brief Function checks length of the IV for modes where inital vector is needed.
 *
 * @param[in] ivLength          Length of the IV
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCipherModes_checkIvLen, mcuxClCipherModes_CheckIvLength_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCipherModes_checkIvLen(
  mcuxClSession_Handle_t session,
  uint32_t ivLength);

#endif /* MCUXCLCIPHERMODES_SGI_AES_IV_H_ */
