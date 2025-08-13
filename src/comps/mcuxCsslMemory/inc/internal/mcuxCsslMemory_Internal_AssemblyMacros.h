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
 * @file  mcuxCsslDataIntegrity_AssemblyMacros.h
 * @brief Assembly macros for the data integrity mechanism
 */

#ifndef MCUXCSSLMEMORY_INTERNAL_ASSEMBLYMACROS_H_
#define MCUXCSSLMEMORY_INTERNAL_ASSEMBLYMACROS_H_


#if defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050) || defined (__GNUC__)

.macro MCUX_CSSL_MEMORY_ASM_SEQZ rDst, rSrc, rTmp
    /* First check */
    clz     \rDst, \rSrc
    lsr     \rDst,  #5

    /* Second check */
    clz     \rTmp, \rSrc
    lsr     \rTmp, \rTmp, #5
    and     \rDst, \rDst, \rTmp  /* rDst = 0 if either rDst or rTmp = 0 */

    /* Third check */
    clz     \rTmp, \rSrc
    lsr     \rTmp, \rTmp, #5
    and     \rDst, \rDst, \rTmp  /* rDst = 0 if either rDst or rTmp = 0 */
    .endm

#elif defined(__IASMARM__) || defined(__ICCARM__)

MCUX_CSSL_MEMORY_ASM_SEQZ macro rDst, rSrc, rTmp
    /* First check */
    clz     rDst, rSrc
    lsr     rDst,  #5

    /* Second check */
    clz     rTmp, rSrc
    lsr     rTmp, rTmp, #5
    and     rDst, rDst, rTmp  /* rDst = 0 if either rDst or rTmp = 0 */

    /* Third check */
    clz     rTmp, rSrc
    lsr     rTmp, rTmp, #5
    and     rDst, rDst, rTmp  /* rDst = 0 if either rDst or rTmp = 0 */
    endm

#endif /* defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050) || defined(__GNUC__) */


#endif /* MCUXCSSLMEMORY_INTERNAL_ASSEMBLYMACROS_H_ */
