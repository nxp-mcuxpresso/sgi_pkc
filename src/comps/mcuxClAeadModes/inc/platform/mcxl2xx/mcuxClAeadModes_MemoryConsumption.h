/*--------------------------------------------------------------------------*/
/* Copyright 2021-2024 NXP                                                  */
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

/** @file  mcuxClAeadModes_MemoryConsumption.h
 *  @brief Defines the memory consumption for the mcuxClAeadModes component */

#ifndef MCUXCLAEADMODES_MEMORYCONSUMPTION_H_
#define MCUXCLAEADMODES_MEMORYCONSUMPTION_H_

#include <mcuxClCore_Macros.h>

/**
 * @defgroup mcuxClAeadModes_MemoryConsumption mcuxClAeadModes_MemoryConsumption
 * @brief Defines the memory consumption for the mcuxClAead component
 *        All work area sizes in bytes are a multiple of CPU wordsize.
 * @ingroup mcuxClAeadModes
 * @{
 */

#define MCUXCLAEAD_ENCRYPT_CPU_WA_BUFFER_SIZE          (696u)
#define MCUXCLAEAD_ENCRYPT_CPU_WA_BUFFER_SIZE_IN_WORDS MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_ENCRYPT_CPU_WA_BUFFER_SIZE )
#define MCUXCLAEAD_DECRYPT_CPU_WA_BUFFER_SIZE          (696u)
#define MCUXCLAEAD_DECRYPT_CPU_WA_BUFFER_SIZE_IN_WORDS  MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_DECRYPT_CPU_WA_BUFFER_SIZE )

#define MCUXCLAEAD_INIT_ENCRYPT_CPU_WA_BUFFER_SIZE          (272u)
#define MCUXCLAEAD_INIT_ENCRYPT_CPU_WA_BUFFER_SIZE_IN_WORDS MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_INIT_ENCRYPT_CPU_WA_BUFFER_SIZE )
#define MCUXCLAEAD_INIT_DECRYPT_CPU_WA_BUFFER_SIZE          (272u)
#define MCUXCLAEAD_INIT_DECRYPT_CPU_WA_BUFFER_SIZE_IN_WORDS MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_INIT_DECRYPT_CPU_WA_BUFFER_SIZE )



#define MCUXCLAEAD_INIT_CPU_WA_BUFFER_SIZE                   (272u)
#define MCUXCLAEAD_INIT_CPU_WA_BUFFER_SIZE_IN_WORDS          MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_INIT_CPU_WA_BUFFER_SIZE)
#define MCUXCLAEAD_PROCESS_CPU_WA_BUFFER_SIZE                (272u)
#define MCUXCLAEAD_PROCESS_CPU_WA_BUFFER_SIZE_IN_WORDS       MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_PROCESS_CPU_WA_BUFFER_SIZE)
#define MCUXCLAEAD_PROCESS_ADATA_CPU_WA_BUFFER_SIZE          (272u)
#define MCUXCLAEAD_PROCESS_ADATA_CPU_WA_BUFFER_SIZE_IN_WORDS MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_PROCESS_ADATA_CPU_WA_BUFFER_SIZE )
#define MCUXCLAEAD_FINISH_CPU_WA_BUFFER_SIZE                 (272u)
#define MCUXCLAEAD_FINISH_CPU_WA_BUFFER_SIZE_IN_WORDS        MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_FINISH_CPU_WA_BUFFER_SIZE )
#define MCUXCLAEAD_VERIFY_CPU_WA_BUFFER_SIZE                 (272u)
#define MCUXCLAEAD_VERIFY_CPU_WA_BUFFER_SIZE_IN_WORDS        MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_VERIFY_CPU_WA_BUFFER_SIZE )
#define MCUXCLAEAD_MAX_CPU_WA_BUFFER_SIZE                    (696u)
#define MCUXCLAEAD_MAX_CPU_WA_BUFFER_SIZE_IN_WORDS           MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_MAX_CPU_WA_BUFFER_SIZE )

#define MCUXCLAEAD_CONTEXT_SIZE (424u)


#define MCUXCLAEAD_WA_SIZE_MAX (696u)
#define MCUXCLAEAD_WA_SIZE_IN_WORDS_MAX     MCUXCLCORE_NUM_OF_CPUWORDS_FLOOR(MCUXCLAEAD_WA_SIZE_MAX )

/**
 * @}
 */ /* mcuxClAead_MemoryConsumption */

#endif /* MCUXCLAEADMODES_MEMORYCONSUMPTION_H_ */
