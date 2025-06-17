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
 * @file  mcuxClFfdh_MemoryConsumption.h
 * @brief Defines the memory consumption for the mcuxClFfdh component
 */

#ifndef MCUXCLFFDH_MEMORYCONSUMPTION_H_
#define MCUXCLFFDH_MEMORYCONSUMPTION_H_

#include <mcuxClCore_Macros.h>

/**
 * @defgroup mcuxClFfdh_MemoryConsumption mcuxClFfdh_MemoryConsumption
 * @brief Defines the memory consumption for the @ref mcuxClFfdh component
 * @ingroup mcuxClFfdh
 * @{
 */

/**
 * @addtogroup MCUXCLFFDH_WACPU
 * @brief Define the CPU workarea size required by mcuxClFfdh APIs.
 * @{
 */

#define MCUXCLKEY_AGREEMENT_FFDH_WACPU_SIZE_2048 (356u )  ///< CPU workarea size (in bytes) for ffdhe2048 #mcuxClKey_agreement.
#define MCUXCLKEY_AGREEMENT_FFDH_WACPU_SIZE_3072 (356u )  ///< CPU workarea size (in bytes) for ffdhe3072 #mcuxClKey_agreement.
#define MCUXCLKEY_AGREEMENT_FFDH_WACPU_SIZE_4096 (356u )  ///< CPU workarea size (in bytes) for ffdhe4096 #mcuxClKey_agreement.
#define MCUXCLKEY_AGREEMENT_FFDH_WACPU_SIZE_6144 (356u )  ///< CPU workarea size (in bytes) for ffdhe6144 #mcuxClKey_agreement.
#define MCUXCLKEY_AGREEMENT_FFDH_WACPU_SIZE_8192 (1384u )  ///< CPU workarea size (in bytes) for ffdhe8192 #mcuxClKey_agreement.

/**
 * @}
 */  /* MCUXCLFFDH_WACPU */


/**
 * @addtogroup MCUXCLFFDH_WAPKC
 * @brief Define the PKC workarea size required by mcuxClFfdh APIs.
 * @{
 */

/**
 * @brief PKC wordsize in FFDH component.
 */
#define MCUXCLFFDH_PKC_WORDSIZE  8u

/**
 * PKC workarea size (in bytes) for #mcuxClFfdh_FFDH_KeyAgreement for arbitrary lengths of p.
 */
#define MCUXCLKEY_AGREEMENT_FFDH_WAPKC_SIZE_2048 (2448u )  ///< PKC workarea size (in bytes) for ffdhe2048 #mcuxClKey_agreement.
#define MCUXCLKEY_AGREEMENT_FFDH_WAPKC_SIZE_3072 (3600u )  ///< PKC workarea size (in bytes) for ffdhe3072 #mcuxClKey_agreement.
#define MCUXCLKEY_AGREEMENT_FFDH_WAPKC_SIZE_4096 (4752u )  ///< PKC workarea size (in bytes) for ffdhe4096 #mcuxClKey_agreement.
#define MCUXCLKEY_AGREEMENT_FFDH_WAPKC_SIZE_6144 (7056u )  ///< PKC workarea size (in bytes) for ffdhe6144 #mcuxClKey_agreement.
#define MCUXCLKEY_AGREEMENT_FFDH_WAPKC_SIZE_8192 (7328u )  ///< PKC workarea size (in bytes) for ffdhe8192 #mcuxClKey_agreement.


/**
 * @}
 */  /* MCUXCLFFDH_WAPKC */


/**
 * @}
 */  /* mcuxClFfdh_MemoryConsumption */

#endif /* MCUXCLFFDH_MEMORYCONSUMPTION_H_ */
