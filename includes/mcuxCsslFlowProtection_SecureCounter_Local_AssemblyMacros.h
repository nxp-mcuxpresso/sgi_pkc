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
 * @file  mcuxCsslFlowProtection_SecureCounter_Local_AssemblyMacros.h
 * @brief Assembly macros for Counter based implementation for the flow protection mechanism, for a local security counter.
 */

#ifndef MCUXCSSLFLOWPROTECTION_SECURECOUNTER_LOCAL_ASSEMBLYMACROS_H_
#define MCUXCSSLFLOWPROTECTION_SECURECOUNTER_LOCAL_ASSEMBLYMACROS_H_

#include <mcuxCsslSecureCounter_AssemblyMacros.h>

/**
 * @def MCUX_CSSL_FP_FUNCTION_ID_ENTRY_EXIT_MASK
 * @brief Mask to be used to derive entry and exit parts from a function identifier
 * @ingroup csslFpCntFunction
 */
/* TODO: CLNS-18893 - Refactor header files to extract constants and prevent code duplication */
#define MCUX_CSSL_FP_FUNCTION_ID_ENTRY_EXIT_MASK  0x5A5A5A5A

#if defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050) || defined(__GNUC__)

.macro MCUX_CSSL_FP_ASM_FUNCTION_ENTRY rSc, rTmp, funcID
  MCUX_CSSL_SC_ASM_INIT_BASE \rSc
  ldr                       \rTmp, =(\funcID & MCUX_CSSL_FP_FUNCTION_ID_ENTRY_EXIT_MASK)
  MCUX_CSSL_SC_ASM_ADD       \rSc,  \rTmp
  .endm

.macro MCUX_CSSL_FP_ASM_FUNCTION_CALL rSc, func
  bl                        \func
  MCUX_CSSL_SC_ASM_ADD       \rSc, r1
  .endm

.macro MCUX_CSSL_FP_ASM_FUNCTION_EXIT rSc, rTmp, funcID
  ldr                       \rTmp, =(\funcID - (\funcID & MCUX_CSSL_FP_FUNCTION_ID_ENTRY_EXIT_MASK))
  MCUX_CSSL_SC_ASM_ADD       \rSc,  \rTmp   /* rSc = VALUE(fn_identifier) - VALUE(fn_identifier) & EXIT_MASK */
  .endm

#elif defined(__IASMARM__) || defined(__ICCARM__)

MCUX_CSSL_FP_ASM_FUNCTION_ENTRY macro rSc, rTmp, funcID
  MCUX_CSSL_SC_ASM_INIT_BASE rSc
  ldr                       rTmp, =(funcID & MCUX_CSSL_FP_FUNCTION_ID_ENTRY_EXIT_MASK)
  MCUX_CSSL_SC_ASM_ADD       rSc,  rTmp
  endm

MCUX_CSSL_FP_ASM_FUNCTION_CALL macro rSc, func
  bl                        func
  MCUX_CSSL_SC_ASM_ADD       rSc, r1
  endm

MCUX_CSSL_FP_ASM_FUNCTION_EXIT macro rSc, rTmp, funcID
  ldr                       rTmp, =(funcID - (funcID & MCUX_CSSL_FP_FUNCTION_ID_ENTRY_EXIT_MASK))
  MCUX_CSSL_SC_ASM_ADD       rSc,  rTmp   /* rSc = VALUE(fn_identifier) - VALUE(fn_identifier) & EXIT_MASK */
  endm

#endif /* defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050) || defined(__GNUC__) */

#endif /* MCUXCSSLFLOWPROTECTION_SECURECOUNTER_LOCAL_ASSEMBLYMACROS_H_ */
