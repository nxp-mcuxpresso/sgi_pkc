/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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

#ifndef MCUXCLMACMODES_COMMON_TYPES_H_
#define MCUXCLMACMODES_COMMON_TYPES_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClBuffer.h>

#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClMacModes_Common_Constants.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief GMAC specific mode descriptor structure
 *
 * This structure captures all the additional information for the GMAC implementation
 * that is not contained in the @ref mcuxClMac_CommonModeDescriptor_t type.
 */
typedef struct mcuxClMacModes_GmacModeDescriptor
{
  mcuxCl_InputBuffer_t pIv;
  uint32_t ivLength;
} mcuxClMacModes_GmacModeDescriptor_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMACMODES_COMMON_TYPES_H_ */
