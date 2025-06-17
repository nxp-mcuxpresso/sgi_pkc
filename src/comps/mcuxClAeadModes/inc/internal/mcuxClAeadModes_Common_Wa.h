/*--------------------------------------------------------------------------*/
/* Copyright 2021-2024 NXP                                                  */
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

/** @file  mcuxClAeadModes_Common_Wa.h
 *  @brief Internal structure of the work space for the mcuxClAeadModes component
 */

#ifndef MCUXCLAEADMODES_COMMON_WA_H_
#define MCUXCLAEADMODES_COMMON_WA_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxClAes_Constants.h>

#include <internal/mcuxClAeadModes_Common_Constants.h>
#include <internal/mcuxClAes_Wa.h>
#include <internal/mcuxClMac_Internal_Types.h>
#include <internal/mcuxClMacModes_Common_Types.h>

#include <internal/mcuxClCipherModes_Common_Wa.h>

typedef union mcuxClAeadModes_CpuWorkArea
{
    uint8_t CCM_B0[MCUXCLAEADMODES_CCM_B0_SIZE];
    uint8_t tagBuffer[2u * MCUXCLAEADMODES_TAGLEN_MAX];
    uint8_t lastBlockBuffer[MCUXCLAES_BLOCK_SIZE - 1u];
} mcuxClAeadModes_CpuWorkArea_t;


typedef struct mcuxClAeadModes_WorkArea
{
  mcuxClAes_Workarea_Sgi_t sgiWa;
  mcuxClAeadModes_CpuWorkArea_t cpuWa;
  uint32_t gmacModeDescBuf[MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClMac_ModeDescriptor_t))
                           + MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClMacModes_GmacModeDescriptor_t))];
} mcuxClAeadModes_WorkArea_t;

#endif /* MCUXCLAEADMODES_COMMON_WA_H_ */
