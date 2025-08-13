/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @file  mcuxClSession_Internal_EntryExit_EarlyExit_Entry_asm.S
 */

#include <mcuxCsslDataIntegrity_AssemblyMacros.h>
#include <mcuxClSession_Internal_AssemblyHeader.h>

#define rPSession      r0      /* pSession, pointer to the session */
#define rPCallCtx      r1      /* pCallCtx, pointer to the new call context to be filled */
#define rFaultStatus   r2      /* faultStatus, fault status value for the current API. */
#define rPSfr          r3      /* base address of DI SFR */
#define rDI            r12     /* current DI value */
#define rAPIcall       r12     /* session->apiCall */

#ifdef __IASMARM__
    NAME mcuxClSession_entry
    SECTION .text:CODE(2)
    PUBLIC  mcuxClSession_entry
#else
.syntax unified
.thumb
.section .text.mcuxClSession_entry, "ax"
.global        mcuxClSession_entry
.type          mcuxClSession_entry, "function"
#endif

/**
* void mcuxClSession_entry(session, pCallCtx, faultStatus)
* r0 = session
* r1 = pCallCtx
* r2 = faultStatus
*/
mcuxClSession_entry:
    /* Save faultStatus to pCallCtx */
    str rFaultStatus, [rPCallCtx, #FAULTSTATUS_OFFSET]

    /* Save old session->apiCall to pCallCtx */
    ldr rAPIcall, [rPSession, #APICALL_OFFSET]
    str rAPIcall, [rPCallCtx, #PREVIOUS_OFFSET]

    /* Save CPU registers to prepare longjump on early exit */
    str r4, [rPCallCtx, #CPUREGISTERBACKUP_S(0)]
    str r5, [rPCallCtx, #CPUREGISTERBACKUP_S(1)]
    str r6, [rPCallCtx, #CPUREGISTERBACKUP_S(2)]
    str r7, [rPCallCtx, #CPUREGISTERBACKUP_S(3)]
    str r8, [rPCallCtx, #CPUREGISTERBACKUP_S(4)]
    str r9, [rPCallCtx, #CPUREGISTERBACKUP_S(5)]
    str r10, [rPCallCtx, #CPUREGISTERBACKUP_S(6)]
    str r11, [rPCallCtx, #CPUREGISTERBACKUP_S(7)]
    str lr, [rPCallCtx, #CPUREGISTERBACKUP_RA]
    str sp, [rPCallCtx, #CPUREGISTERBACKUP_SP]

    /* Write completed call context to session */
    str rPCallCtx, [rPSession, #APICALL_OFFSET]

    /* Return to user and indicate successful API function entry */
    ldr r0, =MCUXCLSESSION_STATUS_ASM_API_ENTERED
    bx lr

#ifdef __IASMARM__
    END
#else
.mcuxClSession_entry_End:
.size       mcuxClSession_entry, .mcuxClSession_entry_End - mcuxClSession_entry
#endif
