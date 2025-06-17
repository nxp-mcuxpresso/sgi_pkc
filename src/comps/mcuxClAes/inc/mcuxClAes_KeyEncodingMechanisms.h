/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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
 * @file  mcuxClAes_KeyEncodingMechanisms.h
 * @brief Definition of internal key types in mcuxClAes component
 */

#ifndef MCUXCLAES_KEYENCODINGMECHANISMS_H_
#define MCUXCLAES_KEYENCODINGMECHANISMS_H_

#include <mcuxClKey_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @defgroup mcuxClAes_EncodingMechanisms mcuxClAes_EncodingMechanisms
 * @brief Mechanisms used by the Aes operations.
 * @ingroup mcuxClAes
 * @{
 */

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED("Consumed by user / customer. Hence, it is declared but never referenced. ")


/**
 * @brief Key encoding descriptor for RFC3394 key wrap/unwrap.
 */
extern const mcuxClKey_EncodingDescriptor_t mcuxClAes_EncodingDescriptor_Rfc3394;

/**
 * @brief Key encoding for RFC3394 key wrap/unwrap.
 */
static const mcuxClKey_Encoding_t mcuxClAes_Encoding_Rfc3394 =
  &mcuxClAes_EncodingDescriptor_Rfc3394;

MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_REFERENCED()

/** @} */


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAES_KEYENCODINGMECHANISMS_H_ */
