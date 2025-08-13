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

/**
 * @file  mcuxClDma_FeatureConfig.h
 * @brief Internal feature flag configurations for DMA features, including consistency checks
 */

#ifndef MCUXCLDMA_FEATURECONFIG_H_
#define MCUXCLDMA_FEATURECONFIG_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <stdbool.h>


/*
 * This file collects all dependencies of DMA driver functionality
 * to other components and checks the platform's feature flags config
 * for consistency in the DMA domain.
 * Public feature flags are translated into internal DMA features
 * which are used for guarding functions. This is needed to avoid the
 * inclusion of driver functions, which are not used at all in the
 * current platform's feature scope, in the build.
 * The aim of these internally defined feature flags is to have
 * sounding names for function inclusion guards, and to have a single
 * point of translation from public features to all internal
 * usages.
 */

/*************************************************************/
/* Internal DMA driver features depending on available modes */
/*************************************************************/

#define MCUXCLDMA_FEATURE_INTERNAL_INTERRUPT_HANDLING              1U


/* DMA-SGI input-handshake functionality is only needed by MAC NonBlocking modes */
#define MCUXCLDMA_FEATURE_INTERNAL_SGI_INPUT_HANDSHAKES            1U


/* DMA-SGI input-output-handshake functionality is only needed by Cipher NonBlocking modes */
#define MCUXCLDMA_FEATURE_INTERNAL_SGI_INPUT_OUTPUT_HANDSHAKES     1U

/* Reading the BITER field is only needed by Cipher NonBlocking modes */
#define MCUXCLDMA_FEATURE_INTERNAL_READ_CITER                      1U

/* Functionality to check for channel errors is only needed in ISRs for NonBlocking modes that use a single DMA channel */
#define MCUXCLDMA_FEATURE_INTERNAL_CHECKFORCHANNELERRORS           1U

/* Functionality to copy AES-blocks hardcoded with the DMA is only needed by CipherModes and MacModes NonBlocking modes */
#define MCUXCLDMA_FEATURE_INTERNAL_HARDCODED_SGI_COPY              1U
/* Copying with a DMA channel is currently only needed by CipherModes and MacModes NonBlocking modes */
#define MCUXCLDMA_FEATURE_INTERNAL_HARDCODED_COPY                  1U

#endif /* MCUXCLDMA_FEATURECONFIG_H_ */
