/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
/*                                                                          */
/* NXP Proprietary. This software is owned or controlled by NXP and may     */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms.  If you do not agree to be bound by the applicable        */
/* license terms, then you may not retain, install, activate or otherwise   */
/* use the software.                                                        */
/*--------------------------------------------------------------------------*/

/**
 * @file  mcuxCsslMemory_Internal_CopyRev_arm_asm.S
 */


#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection_SecureCounter_Local_AssemblyMacros.h>
#include <mcuxCsslDataIntegrity_AssemblyMacros.h>

#define rPTgt        r0              /* pTargetX, current pointer to target buffer */
#define rPSrc        r1              /* pSourceX, current pointer to source buffer */
#define rN           r2              /* length, length of the data to be copied */
#define rT           r3              /* data, temporary register to hold loaded data */
#define rX           r4              /* X, loop condition */
#define rSc          r5              /* SC register */

#ifdef __IASMARM__
        NAME mcuxCsslMemory_Int_CopyRev_arm_asm
        PUBLIC mcuxCsslMemory_Int_CopyRev_arm_asm
        SECTION .text:CODE(2)
        THUMB
#else /* armclang */
.syntax unified
.align 2
.section .text.mcuxCsslMemory_Int_CopyRev_arm_asm, "ax"
.global        mcuxCsslMemory_Int_CopyRev_arm_asm
.type          mcuxCsslMemory_Int_CopyRev_arm_asm, %function
#endif

/**
 * void mcuxCsslMemory_Int_CopyRev_arm_asm(pTarget, pSource, length)
 * r0 = pTarget
 * r1 = pSource
 * r2 = length
 */
mcuxCsslMemory_Int_CopyRev_arm_asm:
  push {r3-r5, lr}

  MCUX_CSSL_FP_ASM_FUNCTION_ENTRY  rSc, rT, MCUX_CSSL_FP_FUNCID_mcuxCsslMemory_Int_CopyRev_arm_asm

mcuxCsslMemory_Int_Copy_arm_asm_CheckZeroLength:
  cbz   rN, mcuxCsslMemory_Int_Copy_arm_asm_Return  /* If length is zero */

  /* Count unaligned byte(s) in head of pTarget[]. */
  add   rPSrc, rPSrc, rN            /* Src pointer to the end of pSource: pSrc -> pSource[len] */
  rsb   rX, rPTgt, #0
  ands  rX, rX, #3                  /* Number of unaligned byte(s) */
  beq   mcuxCsslMemory_Int_Copy_arm_asm_CheckRemaining

  cmp   rN, rX                      /* min(len, number of unaligned bytes) */
  it    lo
  movlo rX, rN

  /*
   * Copy unaligned byte(s) to head of pTraget[]
   * for (i = x; i > 0; i-=1)
   */
mcuxCsslMemory_Int_Copy_arm_asm_LoopHeadUnAligned:
  ldrb  rT, [rPSrc, #-1]!           /* Decrease rPSrc before ldrb by 1 (pre-index) */
  strb  rT, [rPTgt], #1             /* Increase rPTgt after strb by 1 (post-index) */
  subs  rN, rN, #1                  /* Decrease remaining length */
  subs  rX, rX, #1                  /* Decrease loop iterator */
  bne   mcuxCsslMemory_Int_Copy_arm_asm_LoopHeadUnAligned


mcuxCsslMemory_Int_Copy_arm_asm_CheckRemaining:
  cmp   rN, #4
  blo   mcuxCsslMemory_Int_Copy_arm_asm_CheckEnd

  /*
   * Copy word(s). pTarget[] is written aligned, but pSource[] might be read unaligned.
   * for (i = n; i >= 4; i-=4)
   */
mcuxCsslMemory_Int_Copy_arm_asm_LoopAligned:
  ldr   rT, [rPSrc, #-4]!            /* Decrease by 4 and then load */
  rev   rT, rT                       /* Reverse value */
  str   rT, [rPTgt], #4              /* Store and then increase rPSrc by 4 */
  subs  rN, rN, #4                   /* Decrease remaining length */
  cmp   rN, #4
  bhs   mcuxCsslMemory_Int_Copy_arm_asm_LoopAligned

mcuxCsslMemory_Int_Copy_arm_asm_CheckEnd:
  cbz   rN, mcuxCsslMemory_Int_Copy_arm_asm_Return

  /*
   * Copy remaining unaligned byte(s) to tail of pTarget[].
   * for (i = n; i > 0; i-=1)
   */
mcuxCsslMemory_Int_Copy_arm_asm_LoopTailUnaligned:
  ldrb  rT, [rPSrc, #-1]!
  strb  rT, [rPTgt], #1
  subs  rN, rN, #1   /* Decrease remaining length  */
  bne   mcuxCsslMemory_Int_Copy_arm_asm_LoopTailUnaligned

mcuxCsslMemory_Int_Copy_arm_asm_Return:
 /*
  * After all iterations, pTgt/pSrc shall point to pTarget[length]/pSource. pTgt/pSrc
  * will be subtract from DI, and the final DI expunge(pTarget + pSource + length).
  * DI -= pTgt + pSrc i.e. = (pTarget + len) + (pSource)
  * .
  */
  MCUX_CSSL_DI_ASM_EXPUNGE rSc, rPTgt
  MCUX_CSSL_DI_ASM_EXPUNGE rSc, rPSrc
  MCUX_CSSL_FP_ASM_FUNCTION_EXIT  rSc, rT, MCUX_CSSL_FP_FUNCID_mcuxCsslMemory_Int_CopyRev_arm_asm

  /* Return to caller with DI -= (pSource + pTarget + length) */
  mov  r1, rSc
  pop {r3-r5, pc}

#ifdef __IASMARM__
        END
#endif
