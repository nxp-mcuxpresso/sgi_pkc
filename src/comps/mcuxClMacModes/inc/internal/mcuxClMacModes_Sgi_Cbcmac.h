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

#ifndef MCUXCLMACMODES_SGI_CBCMAC_H_
#define MCUXCLMACMODES_SGI_CBCMAC_H_

#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_Platform.h>

#include <mcuxClMac_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxClBuffer.h>

#include <internal/mcuxClMacModes_Sgi_Types.h>
#include <internal/mcuxClMacModes_Common_Wa.h>
#include <internal/mcuxClMacModes_Sgi_Ctx.h>

#ifdef __cplusplus
extern "C" {
#endif

/* If not publicly defined, define internally */
#define MCUXCLMAC_CBCMAC_OUTPUT_SIZE                   (16u)                                              ///< Size of CBCMAC output in bytes:       128 bits (16 bytes)
#define MCUXCLMAC_CBCMAC_OUTPUT_SIZE_IN_WORDS          (MCUXCLMAC_CBCMAC_OUTPUT_SIZE / sizeof(uint32_t)) ///< Size of CBCMAC output in bytes:       128 bits (16 bytes)


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/*
 * Engine functions
 */


/**
 * @brief Internal function, which processes input to a CBC-Mac computation.
 *
 * @pre The key has been loaded to SGI.
 *
 * @param[in]  session   Handle for the current CL session.
 * @param[in]  workArea  Pointer to workarea.
 * @param[in]  pContext  Pointer to context.
 * @param[in]  pIn       Pointer to the input to be processed.
 * @param[in]  inLength    Size of input buffer pointed to by @p pIn.
 * @param[out] pProcessedBytes  Number of bytes processed from @p pIn. RFU.
 *
 * @return mcuxClMac_Status_t  Status of the operation
 * @retval MCUXCLMAC_STATUS_FAILURE Operation failed
 * @retval MCUXCLMAC_STATUS_OK      Operation succeeded
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_updateCBCMac, mcuxClMacModes_UpdateFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_updateCBCMac(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *workArea,
  mcuxClMacModes_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  uint32_t * pProcessedBytes
);



/**
 * @brief Internal function, which finalizes a CBC-Mac computation.
 *
 * @pre The subkeys K1 and K2 have been generated.
 *
 * @param[in]  session   Handle for the current CL session.
 * @param[in]  workArea  Pointer to workarea.
 * @param[in]  pContext  Pointer to context.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMacModes_finalizeCBCMac, mcuxClMacModes_FinalizeFunc_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMacModes_finalizeCBCMac(
  mcuxClSession_Handle_t session,
  mcuxClMacModes_WorkArea_t *workArea,
  mcuxClMacModes_Context_t * const pContext);


/**
 * Helper Functions
 */


MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMACMODES_SGI_CBCMAC_H_ */
