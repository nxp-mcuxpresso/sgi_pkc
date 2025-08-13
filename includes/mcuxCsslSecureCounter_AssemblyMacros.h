/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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
 * @file  mcuxCsslSecureCounter_AssemblyMacros.h
 * @brief Assembly macros for the secure counter
 */

#ifndef MCUXCSSLSECURECOUNTER_ASSEMBLYMACROS_H_
#define MCUXCSSLSECURECOUNTER_ASSEMBLYMACROS_H_


#if defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050) || defined(__GNUC__)

.macro MCUX_CSSL_SC_ASM_INIT_BASE baseReg
  mov \baseReg, #0
  .endm

.macro MCUX_CSSL_SC_ASM_VALUE  baseReg, valueReg
  mov  \valueReg, \baseReg
  .endm

.macro MCUX_CSSL_SC_ASM_ADD  baseReg, valueReg
  add  \baseReg, \baseReg, \valueReg
  .endm

.macro MCUX_CSSL_SC_ASM_SUB  baseReg, valueReg
  sub \baseReg, \baseReg, \valueReg
  .endm

#elif defined(__IASMARM__) || defined(__ICCARM__)

MCUX_CSSL_SC_ASM_INIT_BASE macro baseReg
  mov baseReg, #0
  endm

MCUX_CSSL_SC_ASM_VALUE macro baseReg, valueReg
  mov  valueReg, baseReg
  endm

MCUX_CSSL_SC_ASM_ADD macro baseReg, valueReg
  add  baseReg, baseReg, valueReg
  endm

MCUX_CSSL_SC_ASM_SUB macro baseReg, valueReg
  sub  baseReg, baseReg, valueReg
  endm

#endif /* defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050) || defined(__GNUC__) */



#endif /* MCUXCSSLSECURECOUNTER_ASSEMBLYMACROS_H_ */
