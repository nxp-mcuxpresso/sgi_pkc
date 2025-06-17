/*--------------------------------------------------------------------------*/
/* Copyright 2020, 2022-2024 NXP                                            */
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

/** @file  mcuxClAes_KeyTypes.c
 *  @brief Instantiation of the key types supported by the mcuxClAes component. */

#include <mcuxClAes.h>
#include <mcuxClKey.h>
#include <mcuxClCore_Platform.h>

#include <internal/mcuxClAes_Internal_Constants.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>

// fully supported AES key types
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Aes128                 = {.algoId = MCUXCLKEY_ALGO_ID_AES + MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY, .size = MCUXCLAES_AES128_KEY_SIZE, .info = NULL, .plainEncoding = &mcuxClKey_EncodingDescriptor_Plain};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Aes256                 = {.algoId = MCUXCLKEY_ALGO_ID_AES + MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY, .size = MCUXCLAES_AES256_KEY_SIZE, .info = NULL, .plainEncoding = &mcuxClKey_EncodingDescriptor_Plain};

