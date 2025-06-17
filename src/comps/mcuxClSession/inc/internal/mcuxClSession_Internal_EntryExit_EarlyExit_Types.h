/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @file mcuxClSession_Internal_EntryExit_EarlyExit_Types.h
 */


#ifndef MCUXCLSESSION_INTERNAL_ENTRYEXIT_EARLYEXIT_TYPES_H_
#define MCUXCLSESSION_INTERNAL_ENTRYEXIT_EARLYEXIT_TYPES_H_

#define MCUXCLSESSION_STATUS_API_ENTERED         (0x0EEE2E47u)
#define MCUXCLSESSION_STATUS_EXIT_FA             (0x0EEEF0F0u)
#define MCUXCLSESSION_NUMBER_OF_SAVED_REGISTERS  (10u) /* r4-r11, sp, lr */

/**
 * Structure that holds the necessary information to enter/exit CL API functions, including early exit.
 */
struct mcuxClSession_apiCall
{
  uint32_t faultStatus;     ///< status to be returned in case of fault
  uint32_t diBackup;        ///< backup of original value of DI upon entry of CL API function
  struct mcuxClSession_apiCall *previous; ///< To be set in entry and restored in exit of CL API function to allow multiple levels of CL API calls from within CL
  uint32_t cpuRegisterBackup[MCUXCLSESSION_NUMBER_OF_SAVED_REGISTERS]; ///< CPU Register backup for early exit longjump. Needs to hold s0-s11, ra, sp and upcsstate.
};

#endif /* MCUXCLSESSION_INTERNAL_ENTRYEXIT_EARLYEXIT_TYPES_H_ */
