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

#ifndef MCUXCLRANDOMMODES_PRIVATE_EXITGATES_H_
#define MCUXCLRANDOMMODES_PRIVATE_EXITGATES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <mcuxClSession.h>
#include <mcuxClRandom_Types.h>


/**
 * @brief Function to handle OK and ERROR/FAILURE exit
 *
 * Use this function to leave functions on CtrDrbg Function level e.g. init, reseed and
 * generate function in mcuxClRandomModes_NormalMode.c. NOT to be used in FAULT_ATTACK cases.
 * The inside called clean up functions build an abstraction layer. For further details
 * check the specific implementations.
 *
 * @param      session          Handle for the current CL session.
 * @param[in]  statusCode       Return code when cleanup is successful
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandomModes_cleanupOnExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_cleanupOnExit(mcuxClSession_Handle_t session);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLRANDOMMODES_PRIVATE_EXITGATES_H_ */
