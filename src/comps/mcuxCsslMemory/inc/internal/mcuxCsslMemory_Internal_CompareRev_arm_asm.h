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
 * @file  mcuxCsslMemory_Internal_Compare_arm_asm.h
 * @brief Internal header for assembly implementation of the robust memory compare function for ARM Cortex-M3/33.
 */


#ifndef MCUXCSSLMEMORY_INTERNAL_COMPAREREV_ARM_ASM_H_
#define MCUXCSSLMEMORY_INTERNAL_COMPAREREV_ARM_ASM_H_

#include <mcuxCsslMemory.h>

/**
 * @brief Robust memory compare function
 *
 * @param    pLhs      Left-hand side.
 * @param    pRhs      Right-hand side.
 * @param    length    Length (in bytes). Both Lhs and Rhs should be bounded by this length.
 *
 * Data Integrity: Record(status) + Expunge(&pLhs[length] + &pRhs[length])
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxCsslMemory_CompareRev_arm_asm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxCsslMemory_Status_t)
mcuxCsslMemory_CompareRev_arm_asm(
  const uint8_t* pLhs,
  const uint8_t* pRhs,
  uint32_t length
);

#endif /* MCUXCSSLMEMORY_INTERNAL_COMPAREREV_ARM_ASM_H_ */

