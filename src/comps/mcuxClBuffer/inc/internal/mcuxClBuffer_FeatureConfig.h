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
 * @file  mcuxClBuffer_FeatureConfig.h
 * @brief Internal feature flag configurations for mcuxClBuffer features
 */

#ifndef MCUXCLBUFFER_FEATURECONFIG_H_
#define MCUXCLBUFFER_FEATURECONFIG_H_

#include <mcuxClConfig.h> // Exported features flags header


/*
 * This file collects all dependencies of mcuxClBuffer functionality
 * to other components and checks the platform's feature flags config
 * for consistency in the mcuxClBuffer domain.
 * Public feature flags are translated into internal mcuxClBuffer features
 * which are used for guarding functions. This is needed to avoid the
 * inclusion of Buffer object fields and functions, which are not used
 * at all in the current platform's feature scope, in the build.
 * The aim of these internally defined feature flags is to have
 * sounding names for inclusion guards, and to have a single
 * point of translation from public features to all internal
 * usages.
 */

/**********************************************************************/
/* Internal mcuxClBuffer object features depending on available features  */
/**********************************************************************/


#endif /* MCUXCLBUFFER_FEATURECONFIG_H_ */
