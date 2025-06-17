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

/** @file  mcuxClAeadModes_Sgi_Functions.h
 *  @brief Internal function declaration for the mcuxClAeadModes component */

#ifndef MCUXCLAEADMODES_SGI_FUNCTIONS_H_
#define MCUXCLAEADMODES_SGI_FUNCTIONS_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <internal/mcuxClAeadModes_Common_Wa.h>
#include <internal/mcuxClAeadModes_Sgi_Ctx.h>
#include <internal/mcuxClAeadModes_Sgi_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAeadModes_updateMac)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_updateMac(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *const pContext,
  mcuxClAeadModes_WorkArea_t *workArea,
  mcuxCl_InputBuffer_t pIn,
  const uint32_t macInSize);

/**
 * This function implements the two-pass processing of full input blocks for GCM modes using the SGI.
 * Depending on the direction (encrypt vs. decrypt), it follows a Mac-then-Encrypt or Encrypt-then-Mac approach.
 *
 * @param      session   Handle of the current session.
 * @param      pContext  Pointer to the context.
 * @param      workArea  Handle of the CPU workarea.
 * @param[in]  pIn       Pointer to the input buffer.
 * @param[out] pOut      Pointer to the output buffer.  Will be filled with computed data bytes.
 * @param      inSize    Number of bytes in the input buffer to process.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAeadModes_Gcm_processFullBlocks, mcuxClAeadModes_ProcessFullBlocks_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_Gcm_processFullBlocks(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *const pContext,
  mcuxClAeadModes_WorkArea_t *workArea,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  const uint32_t inSize);

/**
 * This function implements the two-pass processing of full input blocks for CCM modes using the SGI.
 * Depending on the direction (encrypt vs. decrypt), it follows a Mac-then-Encrypt or Encrypt-then-Mac approach.
 *
 * @param      session   Handle of the current session.
 * @param      pContext  Pointer to the context.
 * @param      workArea  Handle of the CPU workarea.
 * @param[in]  pIn       Pointer to the input buffer.
 * @param[out] pOut      Pointer to the output buffer.  Will be filled with computed data bytes.
 * @param      inSize    Number of bytes in the input buffer to process.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAeadModes_Ccm_processFullBlocks, mcuxClAeadModes_ProcessFullBlocks_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_Ccm_processFullBlocks(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t *const pContext,
  mcuxClAeadModes_WorkArea_t *workArea,
  mcuxCl_InputBuffer_t pIn,
  mcuxCl_Buffer_t pOut,
  const uint32_t inSize);

/**
 * This function implements the input data processing step for CCM and GCM modes using the SGI.
 *
 * @param      session   Handle of the current session.
 * @param      pContext  Pointer to the context.
 * @param      workArea  Handle of the CPU workarea.
 * @param[in]  pIn       Pointer to the input buffer.
 * @param      inSize    Number of bytes in the input buffer.
 * @param[out] pOut      Pointer to the output buffer.  Will be filled with computed data bytes.
 * @param[out] pOutSize  Will be set to the number of bytes written to the output buffer.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAeadModes_CcmGcm_process)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_CcmGcm_process(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t* const pContext,
  mcuxClAeadModes_WorkArea_t* workArea,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inSize,
  mcuxCl_Buffer_t pOut,
  uint32_t* const pOutSize
);

/**
 * This function implements the finish step for CCM and GCM modes using the SGI.
 *
 * Data Integrity: Expunge(pTag)
 *
 * @param      session   Handle of the current session.
 * @param      pContext  Pointer to the multipart context.
 * @param      workArea  Handle of the CPU workarea.
 * @param[out] pOut      Pointer to the output buffer. Will be filled with computed data.
 * @param[out] pOutSize  Will be set to the number of bytes written to the output buffer.
 * @param[out] pTag      Pointer to the tag buffer. Will be filled with the computed tag.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAeadModes_CcmGcm_finish, mcuxClAeadModes_alg_finish_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAeadModes_CcmGcm_finish(
  mcuxClSession_Handle_t session,
  mcuxClAeadModes_Context_t* const pContext,
  mcuxClAeadModes_WorkArea_t* workArea,
  mcuxCl_Buffer_t pOut,
  uint32_t* const pOutSize,
  mcuxCl_Buffer_t pTag
);


/* Static inline helper function for violation-free casts in code */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_castToAeadModesContext)
static inline mcuxClAeadModes_Context_t* mcuxClAeadModes_castToAeadModesContext(mcuxClAead_Context_t* pContext)
{
  MCUX_CSSL_ANALYSIS_START_CAST_TO_MORE_SPECIFIC_TYPE()
  return (mcuxClAeadModes_Context_t*) pContext;
  MCUX_CSSL_ANALYSIS_STOP_CAST_TO_MORE_SPECIFIC_TYPE()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_castToAeadModesWorkArea)
static inline mcuxClAeadModes_WorkArea_t* mcuxClAeadModes_castToAeadModesWorkArea(uint32_t* pWa)
{
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClAeadModes_WorkArea_t *) pWa;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_castToMacModesWorkArea)
static inline mcuxClMacModes_WorkArea_t* mcuxClAeadModes_castToMacModesWorkArea(mcuxClAeadModes_WorkArea_t * pWa)
{
  /* All fields that are used in the casted-to type are common in {Cipher/Mac/Aead}Modes workarea structs */
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClMacModes_WorkArea_t*) pWa;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_castToCipherModesWorkArea)
static inline mcuxClCipherModes_WorkArea_t * mcuxClAeadModes_castToCipherModesWorkArea(mcuxClAeadModes_WorkArea_t * pWa)
{
  /* All fields that are used in the casted-to type are common in {Cipher/Mac/Aead}Modes workarea structs */
  MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
  return (mcuxClCipherModes_WorkArea_t*) pWa;
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAeadModes_castToAeadModesAlgorithmDescriptor)
static inline const mcuxClAeadModes_AlgorithmDescriptor_t* mcuxClAeadModes_castToAeadModesAlgorithmDescriptor(const struct mcuxClAead_AlgorithmDescriptor* pAlgorithm)
{
  MCUX_CSSL_ANALYSIS_START_CAST_TO_MORE_SPECIFIC_TYPE()
  return (const mcuxClAeadModes_AlgorithmDescriptor_t*) pAlgorithm;
  MCUX_CSSL_ANALYSIS_STOP_CAST_TO_MORE_SPECIFIC_TYPE()
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /*MCUXCLAEADMODES_SGI_FUNCTIONS_H_*/
