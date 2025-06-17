/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

/** @file  mcuxClHashModes_MemoryConsumption.h
 *  @brief Defines the memory consumption for the mcuxClHash component */

#ifndef MCUXCLHASHMODES_MEMORYCONSUMPTION_H_
#define MCUXCLHASHMODES_MEMORYCONSUMPTION_H_

/**
 * @defgroup mcuxClHashModes_MemoryConsumption mcuxClHashModes_MemoryConsumption
 * @brief Definitions of workarea sizes for the mcuxClHashModes functions.
 * @ingroup mcuxClHashModes
 * @{
 */

/****************************************************************************/
/* Definitions of workarea buffer sizes for the mcuxClHashModes functions.   */
/****************************************************************************/


#define MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_SHA2_224               (64u)                       ///< Defines the workarea size required for mcuxClHash_compute on SHA2-224
#define MCUXCLHASH_COMPUTE_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_224   (88u)           ///< Defines the workarea size required for mcuxClHash_compute on SHA2-224
#define MCUXCLHASH_PROCESS_CPU_WA_BUFFER_SIZE_SHA2_224               (4u)                       ///< Defines the workarea size required for mcuxClHash_process on SHA2-224
#define MCUXCLHASH_PROCESS_NON_BLOCKING_CPU_WA_BUFFER_SIZE_SHA2_224  (20u)           ///< Defines the workarea size required for mcuxClHash_process on SHA2-224
#define MCUXCLHASH_FINISH_CPU_WA_BUFFER_SIZE_SHA2_224                (4u)                        ///< Defines the workarea size required for mcuxClHash_finish on SHA2-224
#define MCUXCLHASH_FINISH_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_224    (4u)            ///< Defines the workarea size required for mcuxClHash_finish on SHA2-224

#define MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_SHA2_256               (64u)                       ///< Defines the workarea size required for mcuxClHash_compute on SHA2-256
#define MCUXCLHASH_COMPUTE_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_256   (88u)           ///< Defines the workarea size required for mcuxClHash_compute on SHA2-256
#define MCUXCLHASH_PROCESS_CPU_WA_BUFFER_SIZE_SHA2_256               (4u)                       ///< Defines the workarea size required for mcuxClHash_process on SHA2-256
#define MCUXCLHASH_PROCESS_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_256   (20u)           ///< Defines the workarea size required for mcuxClHash_process on SHA2-256
#define MCUXCLHASH_FINISH_CPU_WA_BUFFER_SIZE_SHA2_256                (4u)                        ///< Defines the workarea size required for mcuxClHash_finish on SHA2-256
#define MCUXCLHASH_FINISH_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_256    (4u)            ///< Defines the workarea size required for mcuxClHash_finish on SHA2-256

#define MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_SHA2_384               (128u)                       ///< Defines the workarea size required for mcuxClHash_compute on SHA2-384
#define MCUXCLHASH_COMPUTE_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_384   (152u)           ///< Defines the workarea size required for mcuxClHash_compute on SHA2-384
#define MCUXCLHASH_PROCESS_CPU_WA_BUFFER_SIZE_SHA2_384               (4u)                       ///< Defines the workarea size required for mcuxClHash_process on SHA2-384
#define MCUXCLHASH_PROCESS_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_384   (20u)           ///< Defines the workarea size required for mcuxClHash_process on SHA2-384
#define MCUXCLHASH_FINISH_CPU_WA_BUFFER_SIZE_SHA2_384                (4u)                        ///< Defines the workarea size required for mcuxClHash_finish on SHA2-384
#define MCUXCLHASH_FINISH_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_384    (4u)            ///< Defines the workarea size required for mcuxClHash_finish on SHA2-384

#define MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_SHA2_512                   (128u)                       ///< Defines the workarea size required for mcuxClHash_compute on SHA2-512
#define MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_SHA2_512_224               (128u)                       ///< Defines the workarea size required for mcuxClHash_compute on SHA2-512/224
#define MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_SHA2_512_256               (128u)                       ///< Defines the workarea size required for mcuxClHash_compute on SHA2-512/256
#define MCUXCLHASH_COMPUTE_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512       (152u)           ///< Defines the workarea size required for mcuxClHash_compute on SHA2-512
#define MCUXCLHASH_COMPUTE_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512_224   (4u)       ///< Defines the workarea size required for mcuxClHash_compute on SHA2-512/224
#define MCUXCLHASH_COMPUTE_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512_256   (4u)       ///< Defines the workarea size required for mcuxClHash_compute on SHA2-512/256
#define MCUXCLHASH_PROCESS_CPU_WA_BUFFER_SIZE_SHA2_512                   (4u)                       ///< Defines the workarea size required for mcuxClHash_process on SHA2-512
#define MCUXCLHASH_PROCESS_CPU_WA_BUFFER_SIZE_SHA2_512_224               (4u)                   ///< Defines the workarea size required for mcuxClHash_process on SHA2-512/224
#define MCUXCLHASH_PROCESS_CPU_WA_BUFFER_SIZE_SHA2_512_256               (4u)                   ///< Defines the workarea size required for mcuxClHash_process on SHA2-512/256
#define MCUXCLHASH_PROCESS_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512       (20u)           ///< Defines the workarea size required for mcuxClHash_process on SHA2-512
#define MCUXCLHASH_PROCESS_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512_224   (4u)       ///< Defines the workarea size required for mcuxClHash_process on SHA2-512/224
#define MCUXCLHASH_PROCESS_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512_256   (4u)       ///< Defines the workarea size required for mcuxClHash_process on SHA2-512/256
#define MCUXCLHASH_FINISH_CPU_WA_BUFFER_SIZE_SHA2_512                    (4u)                        ///< Defines the workarea size required for mcuxClHash_finish on SHA2-512
#define MCUXCLHASH_FINISH_CPU_WA_BUFFER_SIZE_SHA2_512_224                (4u)                    ///< Defines the workarea size required for mcuxClHash_finish on SHA2-512/224
#define MCUXCLHASH_FINISH_CPU_WA_BUFFER_SIZE_SHA2_512_256                (4u)                    ///< Defines the workarea size required for mcuxClHash_finish on SHA2-512/256
#define MCUXCLHASH_FINISH_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512        (4u)            ///< Defines the workarea size required for mcuxClHash_finish on SHA2-512
#define MCUXCLHASH_FINISH_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512_224    (4u)        ///< Defines the workarea size required for mcuxClHash_finish on SHA2-512_224
#define MCUXCLHASH_FINISH_NONBLOCKING_CPU_WA_BUFFER_SIZE_SHA2_512_256    (4u)        ///< Defines the workarea size required for mcuxClHash_finish on SHA2-512_256









/** @} */


/**
 * @defgroup mcuxClHashModes_ContextSize mcuxClHashModes_ContextSize
 * @brief Definitions of context sizes and state sizes for extraction of states of a hash operation.
 * @ingroup mcuxClHash_Constants
 * @{
 */

/**************************************************************************************************************/
/* Definitions of context sizes and state buffer sizes for mcuxClHash_export_state and mcuxClHash_import_state  */
/**************************************************************************************************************/


#define MCUXCLHASH_CONTEXT_SIZE_SHA2_224_IN_WORDS                (128u / sizeof(uint32_t))
#define MCUXCLHASH_EXPORT_IMPORT_STATE_SIZE_SHA2_224             (40u)  ///< Defines the state size required for SHA2-224

#define MCUXCLHASH_CONTEXT_SIZE_SHA2_256_IN_WORDS                (128u / sizeof(uint32_t))
#define MCUXCLHASH_EXPORT_IMPORT_STATE_SIZE_SHA2_256             (40u)  ///< Defines the state size required for SHA2-256

#define MCUXCLHASH_CONTEXT_SIZE_SHA2_384_IN_WORDS                (224u / sizeof(uint32_t))
#define MCUXCLHASH_EXPORT_IMPORT_STATE_SIZE_SHA2_384             (80u)  ///< Defines the state size required for SHA2-384

#define MCUXCLHASH_CONTEXT_SIZE_SHA2_512_IN_WORDS                (224u / sizeof(uint32_t))
#define MCUXCLHASH_EXPORT_IMPORT_STATE_SIZE_SHA2_512             (80u)  ///< Defines the state size required for SHA2-512





/** @} */


#endif /* MCUXCLHASHMODES_MEMORYCONSUMPTION_H_ */
