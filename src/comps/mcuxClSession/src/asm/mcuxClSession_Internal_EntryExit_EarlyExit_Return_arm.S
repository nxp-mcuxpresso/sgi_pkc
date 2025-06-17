;/*--------------------------------------------------------------------------*/
;/* Copyright 2024-2025 NXP                                                  */
;/*                                                                          */
;/* NXP Proprietary. This software is owned or controlled by NXP and may     */
;/* only be used strictly in accordance with the applicable license terms.   */
;/* By expressly accepting such terms or by downloading, installing,         */
;/* activating and/or otherwise using the software, you are agreeing that    */
;/* you have read, and that you agree to comply with and are bound by, such  */
;/* license terms. If you do not agree to be bound by the applicable license */
;/* terms, then you may not retain, install, activate or otherwise use the   */
;/* software.                                                                */
;/*--------------------------------------------------------------------------*/


/**
 * @file  mcuxClSession_Internal_EntryExit_EarlyExit_Return_asm.S
 */

#include <mcuxClSession_Internal_AssemblyHeader.h>

#define rReturnCode    r0      /* returnCode, status code of the Clib */ /* UNUSED */
#define rPSession      r1      /* pSession, pointer to the session */
#define rAPIcall       r12     /* session->apiCall */

#ifdef __IASMARM__
    NAME mcuxClSession_return
    SECTION .text:CODE(2)
    PUBLIC  mcuxClSession_return
#else
.syntax unified
.thumb
.section .text.mcuxClSession_return, "ax"
.global        mcuxClSession_return
.type          mcuxClSession_return, "function"
#endif

/**
 * void mcuxClSession_return(returnCode, session)
 * r0 = returnCode
 * r1 = session
 */
mcuxClSession_return:

    /* Restore CPU registers to prepare longjump */
    ldr rAPIcall, [rPSession, #APICALL_OFFSET]

    ldr r4, [rAPIcall, #CPUREGISTERBACKUP_S(0)]
    ldr r5, [rAPIcall, #CPUREGISTERBACKUP_S(1)]
    ldr r6, [rAPIcall, #CPUREGISTERBACKUP_S(2)]
    ldr r7, [rAPIcall, #CPUREGISTERBACKUP_S(3)]
    ldr r8, [rAPIcall, #CPUREGISTERBACKUP_S(4)]
    ldr r9, [rAPIcall, #CPUREGISTERBACKUP_S(5)]
    ldr r10, [rAPIcall, #CPUREGISTERBACKUP_S(6)]
    ldr r11, [rAPIcall, #CPUREGISTERBACKUP_S(7)]
    ldr lr, [rAPIcall, #CPUREGISTERBACKUP_RA]
    ldr sp, [rAPIcall, #CPUREGISTERBACKUP_SP]

    /* Perform longjump to lr extracted from session->apiCall */
    bx lr

#ifdef __IASMARM__
    END
#else
.mcuxClSession_return_End:
.size       mcuxClSession_return, .mcuxClSession_return_End - mcuxClSession_return
#endif
