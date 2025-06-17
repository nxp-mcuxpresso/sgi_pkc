/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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
 * @file  mcuxClAes_Internal_Functions.h
 * @brief Internal helper function definitions for the mcuxClAes component
 */

#ifndef MCUXCLAES_INTERNAL_FUNCTIONS_H_
#define MCUXCLAES_INTERNAL_FUNCTIONS_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClKey.h>
#include <mcuxClSgi_Types.h>
#include <mcuxClSgi_Constants.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClAes_Wa.h>
#include <internal/mcuxClAes_Ctx.h>
#include <mcuxClAes_Types.h>
#include <internal/mcuxClKey_Types_Internal.h>

#include <mcuxClResource_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Internal function, which loads a given key and stores it in the SGI.
 * The function evaluates the key type and size and can handle protected keys.
 *
 * This function is an SGI specific function and acts as a wrapper to the
 * key->encoding.loadFunc function, and also sets fields for key details in the
 * workarea, if needed.
 *
 * @post If the key is not preloaded, the key data is loaded to the SGI,
 *       and the key's loadStatus location is updated to @ref MCUXCLKEY_LOADSTATUS_LOCATION_COPRO.
 *       The workarea is updated to reflect the key status and details.
 *
 * @param[in]  session             Current session handle.
 * @param[in]  key                 Handle for the key to be loaded to SGI.
 * @param[in]  pWa                 Pointer to the common workarea fields for Cipher/Mac/Aead.
 *                                 Can also be NULL if not needed.
 * @param[in]  keyOffset           Offset of the target KEY SGI SFR,
 *                                 can be either of these values:
 *                                   #MCUXCLSGI_DRV_KEY0_OFFSET
 *                                   #MCUXCLSGI_DRV_KEY1_OFFSET
 *                                   #MCUXCLSGI_DRV_KEY2_OFFSET
 *                                   #MCUXCLSGI_DRV_KEY3_OFFSET
 *                                   #MCUXCLSGI_DRV_KEY4_OFFSET
 *                                   #MCUXCLSGI_DRV_KEY5_OFFSET
 *                                   #MCUXCLSGI_DRV_KEY6_OFFSET
 *                                   #MCUXCLSGI_DRV_KEY7_OFFSET
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAes_loadKey_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_loadKey_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAes_Workarea_Sgi_t* pWa,
  uint32_t keyOffset
);

/**
 * @brief Internal function to store the key from the SGI to the AES key context.
 *
 * If the key can be read from SGI (key SFR is not WRITE_ONLY), store the key SFR-masked
 * in the context. This function implements masked key storage according to SREQI_BCIPHER_2.
 * If not, store the key handle in the context.
 *
 * @pre Function @ref mcuxClAes_loadKey_Sgi was called to load the key and initialize the workarea.
 * @post The context is updated to reflect the key storage.
 *
 * @param[in]  session   Current session handle.
 * @param[in]  key       Handle for the key to be loaded to SGI.
 * @param[in]  pContext  Pointer to the context, where the key will be stored.
 * @param[in]  pWa       Pointer to the common workarea fields for Cipher/Mac/Aead.
 *                       Can also be NULL if not needed, e.g. when storing Clib internal keys.
 * @param[in]  keyOffset Offset of the target KEY SGI SFR or DATOUT SGI SFR based on MCUXCLSGI_DRV_DATIN0_OFFSET,
 *                       can be either of these values:
 *                         #MCUXCLSGI_DRV_KEY0_OFFSET
 *                         #MCUXCLSGI_DRV_KEY1_OFFSET
 *                         #MCUXCLSGI_DRV_KEY2_OFFSET
 *                         #MCUXCLSGI_DRV_KEY3_OFFSET
 *                         #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in]  keySize   Length of the masked key
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAes_storeMaskedKeyInCtx_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_storeMaskedKeyInCtx_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  mcuxClAes_KeyContext_Sgi_t * const pContext,
  mcuxClAes_Workarea_Sgi_t* pWa,
  uint32_t keyOffset,
  uint32_t keySize);

/**
 * @brief Internal function to load the key from the AES key context to the SGI.
 *
 * This function implements masked key loading according to SREQI_BCIPHER_2.
 * It shall also be used for loading Clib internal keys (subkeys, H-Key, ..), or for
 * re-loading keys that could not be stored in context due to WRITE_ONLY SGI key registers (rfc3394).
 *
 * If the key was stored SFR masked in the context, copy it back to SGI. This implements
 * masked key loading from context according to SREQI_BCIPHER_2.
 * If not, freshly load the key into the SGI with the key handle in the context.
 *
 * @pre Function @ref mcuxClAes_storeMaskedKeyInCtx_Sgi was called to store the key and
 *      update the context.
 * @post The context and/or workarea are updated to reflect the key load status and details.
 *
 * @param[in]  session   Current session handle.
 * @param[in]  pContext  Pointer to the context, from which the key will be loaded.
 * @param[in]  pWa       Pointer to the common workarea fields for Cipher/Mac/Aead.
 *                       Can also be NULL if not needed, e.g. when loading Clib internal keys.
 * @param[in]  keyOffset Offset of the target KEY SGI SFR or DATIN SGI SFR,
 *                       can be either of these values:
 *                         #MCUXCLSGI_DRV_KEY0_OFFSET
 *                         #MCUXCLSGI_DRV_KEY1_OFFSET
 *                         #MCUXCLSGI_DRV_KEY2_OFFSET
 *                         #MCUXCLSGI_DRV_KEY3_OFFSET
 *                         #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                         #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                         #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                         #MCUXCLSGI_DRV_DATIN3_OFFSET
 * @param[in]  keySize   Length of the masked key
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAes_loadMaskedKeyFromCtx_Sgi)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_loadMaskedKeyFromCtx_Sgi(
  mcuxClSession_Handle_t session,
  mcuxClAes_KeyContext_Sgi_t * const pContext,
  mcuxClAes_Workarea_Sgi_t* pWa,
  uint32_t keyOffset,
  uint32_t keySize);

/**
 * @brief Internal function to flush the key in the context from its SGI key slot.
 *
 * This function flushes the key in the context from the SGI in case the key was
 * not preloaded by the customer.
 * If the key is preloaded (see @ref MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED),
 * the flush is skipped.
 *
 * @post: If the key is not preloaded, the key in the context is flushed from the SGI, and
 *        the key's loadStatus is updated to @ref MCUXCLKEY_LOADSTATUS_NOT_LOADED.
 *        The context is updated to reflect the changes.
 *
 * @param[in]  session   Current session handle.
 * @param[in]  pContext  Pointer to the context, from which the key will be loaded.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClAes_flushKeyInContext)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_flushKeyInContext(
  mcuxClSession_Handle_t session,
  mcuxClAes_KeyContext_Sgi_t * const pContext);





#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLAES_INTERNAL_FUNCTIONS_H_ */
