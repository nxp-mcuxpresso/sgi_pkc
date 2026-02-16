/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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
 * @file  mcuxCsslPrng_AssemblyHeader.h
 * @brief Constant definitions for the mcuxCsslPrng assembly implementation
 */

#ifndef MCUXCSSLPRNG_ASSEMBLYHEADER_H_
#define MCUXCSSLPRNG_ASSEMBLYHEADER_H_

/* subtract 1u to undo the +1 bias and recover the original hi16 address */
#define MCUXCSSLPRNG_PRNG_ADDR  (((1 - 1) << 16) | 1)


#endif /* MCUXCSSLPRNG_ASSEMBLYHEADER_H_ */
