/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

#ifndef MCUXCLSGI_INTERNAL_TYPES_H_
#define MCUXCLSGI_INTERNAL_TYPES_H_

#include <mcuxCsslFlowProtection.h>
#include <mcuxClBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Function type for wrapper function to copy data out of SGI
 *
 * @param      session             Session handle
 * @param      pWa          Pointer to workarea required by this function
 * @param      pOut         Output buffer to copy data from SGI to
 * @param      offset       Offset in pOut to write data to
 * @param      byteLength   Byte length to copy date from SGI to pOut
 *
 *  Data Integrity: Expunge(pOut + offset + mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET) + byteLength)
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClSgi_copyOut_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClSgi_copyOut_t)(mcuxClSession_Handle_t session, void* pWa, mcuxCl_Buffer_t pOut, uint32_t offset, uint32_t byteLength));


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLSGI_INTERNAL_TYPES_H_ */

