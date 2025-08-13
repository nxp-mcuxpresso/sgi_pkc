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
 * @file  mcuxClSession_MemoryConsumption.h
 * @brief Defines the memory consumption for the mcuxClSession component
 */

#ifndef MCUXCLSESSION_MEMORYCONSUMPTION_H_
#define MCUXCLSESSION_MEMORYCONSUMPTION_H_


#define MCUXCLSESSION_DESCRIPTOR_SIZE           (88u) ///< Total size (in bytes) needed for session descriptor
#define MCUXCLSESSION_DESCRIPTOR_SIZE_IN_WORDS  (MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLSESSION_DESCRIPTOR_SIZE)) ///< Total size (in bytes) needed for session descriptor

#endif /* MCUXCLSESSION_MEMORYCONSUMPTION_H_ */
