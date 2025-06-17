/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023, 2025 NXP                                            */
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

#ifndef MCUXCLSGI_SFR_SEC_H_
#define MCUXCLSGI_SFR_SEC_H_

#include <mcuxCsslFlowProtection.h>
#include <platform_specific_headers.h>
#include <internal/mcuxClSgi_SfrAccess.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Read the SGI COUNT register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_readCount)
static inline uint32_t mcuxClSgi_Sfr_readCount(void)
{

  // TODO CLNS-18218: The SGI_COUNT bit length is 16-bits for certain variants (eg A20), while it is 32-bits for other variants (eg A2ts/W70).
  // This bit differnce for variants will be handled in the ticket together with a feature flag.

  // This workaround shall be only done for when the SGI_COUNT is 16-bits.
  return MCUXCLSGI_SFR_READ(COUNT) & 0xFFFFU;
}

/**
 * Write the SGI COUNT register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_writeCount)
static inline void mcuxClSgi_Sfr_writeCount(uint32_t value)
{
  MCUXCLSGI_SFR_WRITE(COUNT, value);
}

/**
 * Read the SGI KEYCHK register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_readKeyChk)
static inline uint32_t mcuxClSgi_Sfr_readKeyChk(void)
{
  return MCUXCLSGI_SFR_READ(KEYCHK);
}

/**
 * Write the SGI KEYCHK register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_writeKeyChk)
static inline void mcuxClSgi_Sfr_writeKeyChk(uint32_t value)
{
  MCUXCLSGI_SFR_WRITE(KEYCHK, value);
}

/**
 * Read the SGI SEED register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_readSfrSeed)
static inline uint32_t mcuxClSgi_Sfr_readSfrSeed(void)
{
  return MCUXCLSGI_SFR_READ(SFRSEED);
}

/**
 * Write the SGI SEED register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_writeSfrSeed)
static inline void mcuxClSgi_Sfr_writeSfrSeed(uint32_t value)
{
  MCUXCLSGI_SFR_WRITE(SFRSEED, value);
}

/**
 * Read the SGI DUMMY_CTRL register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_readDummyCtrl)
static inline uint32_t mcuxClSgi_Sfr_readDummyCtrl(void)
{
  return MCUXCLSGI_SFR_READ(DUMMY_CTRL);
}

/**
 * Write the SGI DUMMY_CTRL register
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Sfr_setDummyCtrl)
static inline void mcuxClSgi_Sfr_setDummyCtrl(uint32_t value)
{
  MCUXCLSGI_SFR_WRITE(DUMMY_CTRL, value);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLSGI_SFR_SEC_H_ */
