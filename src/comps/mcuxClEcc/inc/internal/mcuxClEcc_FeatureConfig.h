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
 * @file  mcuxClEcc_FeatureConfig.h
 * @brief Internal feature flag configurations for mcuxClEcc features
 */

#ifndef MCUXCLECC_FEATURECONFIG_H_
#define MCUXCLECC_FEATURECONFIG_H_

#include <mcuxClConfig.h> // Exported features flags header

/*
 * This file collects all dependencies of mcuxClEcc functionality
 * to other components and checks the platform's feature flags config
 * for consistency in the mcuxClEcc domain.
 * Public feature flags are translated into internal mcuxClEcc features
 * which are used for guarding functions. This is needed to avoid the
 * inclusion of Ecc object fields and functions, which are not used
 * at all in the current platform's feature scope, in the build.
 * The aim of these internally defined feature flags is to have
 * sounding names for inclusion guards, and to have a single
 * point of translation from public features to all internal
 * usages.
 */

/**********************************************************************/
/* Internal mcuxClEcc object features depending on available features  */
/**********************************************************************/

/*
 * Internal feature flags for generic ECC point operations
 */
/* Inclusion of the internal Ecc mcuxClEcc_GenerateMultiplicativeBlinding function. */
#define MCUXCLECC_FEATURE_INTERNAL_GENMULTBLINDING

/*
 * Internal feature flags for ECC Weierstrass curves
 */
/* Inclusion of the internal Ecc Weierstrass curves. */
#define MCUXCLECC_FEATURE_INTERNAL_WEIERSTRASS_CURVES

/*
 * Internal feature flags for ECC Weierstrass key types/functions
 */
/* Inclusion of the internal Ecc Weierstrass public key store operation. */
#define MCUXCLECC_FEATURE_INTERNAL_WEIER_PUBKEY_STORAGE

/* Inclusion of the internal Ecc Weierstrass private key store operation. */
#define MCUXCLECC_FEATURE_INTERNAL_WEIER_PRIVKEY_STORAGE

/*
 * Internal feature flags for ECC Weierstrass point arithmetic operations
 */
/* Inclusion of the internal Ecc Weierstrass point conversion operations. */
#define MCUXCLECC_FEATURE_INTERNAL_WEIER_POINT_CONVERSION

/* Inclusion of the internal Ecc Weierstrass secure point mult operations. */
#define MCUXCLECC_FEATURE_INTERNAL_WEIER_SECUREPOINTMULT

/* Inclusion of the internal Ecc Weierstrass mcuxClEcc_IntegrityCheckPN function. */
#define MCUXCLECC_FEATURE_INTERNAL_WEIER_INTEGRITYCHECK_PN

/* Inclusion of the internal Ecc Weierstrass mcuxClEcc_Weier_PointCheckJacMR and mcuxClEcc_Weier_SecureConvertPoint_JacToAffine functions. */
#define MCUXCLECC_FEATURE_INTERNAL_WEIER_JACOBIAN_POINT_CHECK

/* Inclusion of the internal Ecc Weierstrass mcuxClEcc_SecurePointMult function. */
#define MCUXCLECC_FEATURE_INTERNAL_WEIER_SECPOINTMULT

#endif /* MCUXCLECC_FEATURECONFIG_H_ */
