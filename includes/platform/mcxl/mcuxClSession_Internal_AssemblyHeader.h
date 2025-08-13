/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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
 * @file  mcuxClSession_Internal_AssemblyHeader.h
 * @brief Constant definitions for the mcuxClSession Early Exit assembly implementation
 */

#ifndef MCUXCLSESSION_INTERNAL_ASSEMBLYHEADER_H_
#define MCUXCLSESSION_INTERNAL_ASSEMBLYHEADER_H_

#define MCUXCLSESSION_STATUS_ASM_API_ENTERED     ((3822 << 16) | 11847)
#define MCUXCLSESSION_STATUS_ASM_EXIT_FA         ((3822 << 16) | 61680)

#define WORDLEN                     (4)                                   /* CPU word length */
#define APICALL_OFFSET              (85 - 1)                         /* Index of apiCall in struct mcuxClSession_Descriptor */

#define FAULTSTATUS_OFFSET          (1 - 1)              /* Index of faultStatus in struct mcuxClSession_apiCall */
#define DIBACKUP_OFFSET             (5 - 1)                 /* Index of diBackup in struct mcuxClSession_apiCall */
#define PREVIOUS_OFFSET             (9 - 1)                 /* Index of previous in struct mcuxClSession_apiCall */
#define CPUREGISTERBACKUP_OFFSET    (13 - 1)        /* Index of cpuRegisterBackup in struct mcuxClSession_apiCall */

#define CPUREGISTERBACKUP_NUMBEROF_S_REGISTERS  (8)                                             /* Number of S registers to backup */
#define CPUREGISTERBACKUP_S(s_index)            (CPUREGISTERBACKUP_OFFSET + s_index * WORDLEN)  /* Index of S register in cpuRegisterBackup */
#define CPUREGISTERBACKUP_RA                    (CPUREGISTERBACKUP_OFFSET + CPUREGISTERBACKUP_NUMBEROF_S_REGISTERS * WORDLEN)       /* Index of RA register in cpuRegisterBackup */
#define CPUREGISTERBACKUP_SP                    (CPUREGISTERBACKUP_OFFSET + (CPUREGISTERBACKUP_NUMBEROF_S_REGISTERS + 1) * WORDLEN) /* Index of SP register in cpuRegisterBackup */
#define CPUREGISTERBACKUP_UPCSSTATE             (CPUREGISTERBACKUP_OFFSET + (CPUREGISTERBACKUP_NUMBEROF_S_REGISTERS + 2) * WORDLEN) /* Index of UPCSSTATE register in cpuRegisterBackup */


#endif /* MCUXCLSESSION_INTERNAL_ASSEMBLYHEADER_H_ */
