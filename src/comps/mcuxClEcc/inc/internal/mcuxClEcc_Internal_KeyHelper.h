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

#ifndef MCUXCLECC_INTERNAL_KEYHELPER_H_
#define MCUXCLECC_INTERNAL_KEYHELPER_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <internal/mcuxClKey_Internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Define encoding specs for ECC key loads. Generic types/macro are located in mcuxClKey_Internal.h */

/* ECC combined key specs (see @ref MCUXCLKEY_ENCODING_SPEC_COMP_MASK): */
#define MCUXCLECC_ENCODING_SPEC_EDDSA_SUBPRIVKEY_LOAD_SECURE        (MCUXCLKEY_ENCODING_SPEC_ECC_EDDSA_SUBPRIVKEY | MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE)
#define MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEYHALFHASH_PTR           (MCUXCLKEY_ENCODING_SPEC_ECC_EDDSA_PRIVKEYHALFHASH | MCUXCLKEY_ENCODING_SPEC_ACTION_PTR)
#define MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEY_STORE_SECURE          (MCUXCLKEY_ENCODING_SPEC_ECC_EDDSA_PRIVKEY | MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE)
#define MCUXCLECC_ENCODING_SPEC_EDDSA_SUBPRIVKEY_STORE_SECURE       (MCUXCLKEY_ENCODING_SPEC_ECC_EDDSA_SUBPRIVKEY | MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE)
#define MCUXCLECC_ENCODING_SPEC_EDDSA_PRIVKEYHALFHASH_STORE_SECURE  (MCUXCLKEY_ENCODING_SPEC_ECC_EDDSA_PRIVKEYHALFHASH | MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE)



#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_INTERNAL_KEYHELPER_H_ */
