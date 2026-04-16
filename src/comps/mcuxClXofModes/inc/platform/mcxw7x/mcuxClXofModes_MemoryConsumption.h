/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms.  By expressly accepting such terms or by downloading,     */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms.  If you do not agree to be bound by the    */
/* applicable license terms, then you may not retain, install, activate or  */
/* otherwise use the software.                                              */
/*--------------------------------------------------------------------------*/

/** @file  mcuxClXofModes_MemoryConsumption.h
 *  @brief Defines the memory consumption for the mcuxClXofModes component */

#ifndef MCUXCLXOFMODES_MEMORYCONSUMPTION_H_
#define MCUXCLXOFMODES_MEMORYCONSUMPTION_H_

/**
* @defgroup mcuxClXofModes_MemoryConsumption mcuxClXofModes_MemoryConsumption
* @brief Memory consumption of the @ref mcuxClXofModes component
* @ingroup mcuxClXofModes
* @{
*/

/*****************************************************************/
/* Definitions of cpu workarea sizes for the mcuxClXof functions. */
/*****************************************************************/

#define MCUXCLXOF_COMPUTE_CPU_WA_BUFFER_SIZE_MAX                (200u)                  ///< Defines the max workarea size required for mcuxClXof_compute
#define MCUXCLXOF_INIT_CPU_WA_BUFFER_SIZE                       (200u)                     ///< Defines the max workarea size required for mcuxClXof_init
#define MCUXCLXOF_PROCESS_CPU_WA_BUFFER_SIZE_MAX                (200u)                  ///< Defines the max workarea size required for mcuxClXof_process
#define MCUXCLXOF_GENERATE_CPU_WA_BUFFER_SIZE_MAX               (200u)                 ///< Defines the max workarea size required for mcuxClXof_generate
#define MCUXCLXOF_FINISH_CPU_WA_BUFFER_SIZE_MAX                 (200u)                   ///< Defines the max workarea size required for mcuxClXof_finish
#define MCUXCLXOF_MAX_CPU_WA_BUFFER_SIZE                        (200u)                          ///< Defines the max workarea size required for the mcuxClXof component

/****************************************************************************/
/* Definitions of context sizes for the mcuxClXof multi-part functions.      */
/****************************************************************************/

#define MCUXCLXOF_CONTEXT_SIZE                                  (404u)                       ///< @deprecated in favor of algorithm specific context sizes.
#define MCUXCLXOF_CONTEXT_SIZE_IN_WORDS                         (404u / sizeof(uint32_t))    ///< @deprecated in favor of algorithm specific context sizes.

#define MCUXCLXOF_SHAKE128_CONTEXT_SIZE                         (404u)                       ///< Defines the context size of a (C)SHAKE128 instance.
#define MCUXCLXOF_SHAKE128_CONTEXT_SIZE_IN_WORDS                (404u / sizeof(uint32_t))
#define MCUXCLXOF_SHAKE256_CONTEXT_SIZE                         (372u)                       ///< Defines the context size of a (C)SHAKE256 instance.
#define MCUXCLXOF_SHAKE256_CONTEXT_SIZE_IN_WORDS                (372u / sizeof(uint32_t))
#define MCUXCLXOF_SECSHAKE128_CONTEXT_SIZE                      (4u)                    ///< Defines the context size of a SECSHAKE128 instance.
#define MCUXCLXOF_SECSHAKE128_CONTEXT_SIZE_IN_WORDS             (4u / sizeof(uint32_t))
#define MCUXCLXOF_SECSHAKE256_CONTEXT_SIZE                      (4u)                    ///< Defines the context size of a SECSHAKE256 instance.
#define MCUXCLXOF_SECSHAKE256_CONTEXT_SIZE_IN_WORDS             (4u / sizeof(uint32_t))

/** @} */

#endif /* MCUXCLXOFMODES_MEMORYCONSUMPTION_H_ */
