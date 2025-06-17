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

#ifndef MCUXCLSGI_SFR_STATUS_H_
#define MCUXCLSGI_SFR_STATUS_H_

#include <mcuxCsslFlowProtection.h>
#include <platform_specific_headers.h>
#include <internal/mcuxClSgi_SfrAccess.h>


/* Macros for the SGI_STATUS SFR */
#define MCUXCLSGI_SFR_STATUS_ERROR_NO_ERROR  (0x5u) ///< No errors reported in SGI_STATUS.ERROR bits. All other values indicate an error.

#define MCUXCLSGI_SFR_STATUS_ERROR(status) ((MCUXCLSGI_SFR_STATUS_ERROR_NO_ERROR << MCUXCLSGI_SFR_BITPOS(STATUS,ERROR)) != ((status) & MCUXCLSGI_SFR_BITMSK(STATUS,ERROR)))
#define MCUXCLSGI_SFR_STATUS_BUSY(status)  (0u != ((status) & MCUXCLSGI_SFR_BITMSK(STATUS,BUSY)))

#ifdef SGI_HAS_KEY_WRAP_UNWRAP
#define MCUXCLSGI_SFR_STATUS_HAS_KEY_UNWRAP_ERROR(status) (0u != ((status) & MCUXCLSGI_SFR_BITMSK(STATUS,KEY_UNWRAP_ERR)))
#endif /* SGI_HAS_KEY_WRAP_UNWRAP */

#ifdef SGI_HAS_ACCESS_ERR
/* Macros for the SGI_ACCESS_ERR SFR */
#define MCUXCLSGI_SFR_ACCESS_ERROR(accessErr) (0u != (accessErr))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Read the SGI STATUS register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_readStatus)
static inline uint32_t mcuxClSgi_Sfr_readStatus(void)
{
  return MCUXCLSGI_SFR_READ(STATUS);
}

#ifdef SGI_HAS_ACCESS_ERR
/**
 * Read the SGI ACCESS_ERR register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_readAccessError)
static inline uint32_t mcuxClSgi_Sfr_readAccessError(void)
{
  return MCUXCLSGI_SFR_READ(ACCESS_ERR);
}
#endif /* SGI_HAS_ACCESS_ERR */


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLSGI_SFR_STATUS_H_ */
