/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2025 NXP                                                 */
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
 * @file  mcuxCsslMemory_Internal_Copy_m0_asm.h
 * @brief Internal header of core mcuxCsslMemory_Copy asm function for arm m0 only
 */


#ifndef MCUXCSSLMEMORY_INTERNAL_COPY_ARM_ASM_H_
#define MCUXCSSLMEMORY_INTERNAL_COPY_ARM_ASM_H_

#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslMemory.h>

/**
 * @brief Robust memory copy function
 * 
 * @param pTarget    The pointer to the destination
 * @param pSource    The pointer to the source
 * @param length     Length to copy
 * 
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_Int_Copy_arm_asm)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxCsslMemory_Int_Copy_arm_asm(uint8_t *pTarget, const uint8_t* pSource, uint32_t length);

#endif /* MCUXCSSLMEMORY_INTERNAL_COPY_ARM_ASM_H_ */
