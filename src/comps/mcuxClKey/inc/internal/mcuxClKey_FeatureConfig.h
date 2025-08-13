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
 * @file  mcuxClKey_FeatureConfig.h
 * @brief Internal feature flag configurations for mcuxClKey features
 */

#ifndef MCUXCLKEY_FEATURECONFIG_H_
#define MCUXCLKEY_FEATURECONFIG_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <stdbool.h>


/*
 * This file collects all dependencies of mcuxClKey functionality
 * to other components and checks the platform's feature flags config
 * for consistency in the mcuxClKey domain.
 * Public feature flags are translated into internal mcuxClKey features
 * which are used for guarding functions. This is needed to avoid the
 * inclusion of Key object fields and functions, which are not used
 * at all in the current platform's feature scope, in the build.
 * The aim of these internally defined feature flags is to have
 * sounding names for inclusion guards, and to have a single
 * point of translation from public features to all internal
 * usages.
 */

/**********************************************************************/
/* Internal mcuxClKey object features depending on available features  */
/**********************************************************************/

/* Inclusion of the internal Key flush functionality that's associated to a key object.
 * It is currently only used if the public Key_Flush API is enabled, or for AES internal key flush. */
#define MCUXCLKEY_FEATURE_INTERNAL_FLUSH_FUNC

/* Inclusion of the internal Key plain store functionality that's associated to a key object.
 * It is used when plain key data is stored in the key object after key generation or derivation for certain modes. */
#define MCUXCLKEY_FEATURE_INTERNAL_STOREPLAIN_FUNC

/* Inclusion of the internal Key HandleKeyChecksums_None functionality that's associated to a key object.
 * It is currently only used if AES keys are enabled, and is needed for default functionality in case key checksums are not required. */
#define MCUXCLKEY_FEATURE_INTERNAL_HANDLECHECKSUMNONE_FUNC

#endif /* MCUXCLKEY_FEATURECONFIG_H_ */
