/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @file  mcuxClRandomModes_MemoryConsumption.h
 * @brief Defines the memory consumption for the mcuxClRandom component
 */

#ifndef MCUXCLRANDOMMODES_MEMORYCONSUMPTION_H_
#define MCUXCLRANDOMMODES_MEMORYCONSUMPTION_H_

/**
 * @defgroup mcuxClRandomModes_MemoryConsumption mcuxClRandomModes_MemoryConsumption
 * @brief Defines the memory consumption for the @ref mcuxClRandom component
 * @ingroup mcuxClRandomModes
 * @{
 */

#define MCUXCLRANDOMMODES_PATCHMODE_DESCRIPTOR_SIZE     (20u)

#define MCUXCLRANDOMMODES_TESTMODE_DESCRIPTOR_SIZE     (20u)

#define MCUXCLRANDOMMODES_MAX_CPU_WA_BUFFER_SIZE                      (316u)

#define MCUXCLRANDOMMODES_INIT_WACPU_SIZE                             (288u)
#define MCUXCLRANDOMMODES_RESEED_WACPU_SIZE                           (256u)
#define MCUXCLRANDOMMODES_GENERATE_WACPU_SIZE                         (256u)
#define MCUXCLRANDOMMODES_SELFTEST_WACPU_SIZE                         (316u)
#define MCUXCLRANDOMMODES_UNINIT_WACPU_SIZE                           (0u)
#define MCUXCLRANDOMMODES_CHECKSECURITYSTRENGTH_WACPU_SIZE            (0u)
#define MCUXCLRANDOMMODES_CREATEPATCHMODE_WACPU_SIZE                  (0u)
#define MCUXCLRANDOMMODES_CREATETESTMODEFROMNORMALMODE_WACPU_SIZE     (0u)




#define MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE (72u)
#define MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE_IN_WORDS ((MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE + sizeof(uint32_t) - 1u) / sizeof(uint32_t))



#define MCUXCLRANDOMMODES_TESTMODE_CTR_DRBG_AES256_INIT_ENTROPY_SIZE     (64u)
#define MCUXCLRANDOMMODES_TESTMODE_CTR_DRBG_AES256_RESEED_ENTROPY_SIZE   (48u)


#define MCUXCLRANDOMMODES_PATCHMODE_CONTEXT_SIZE        (4u)
#define MCUXCLRANDOMMODES_PATCHMODE_CONTEXT_SIZE_IN_WORDS ((MCUXCLRANDOMMODES_PATCHMODE_CONTEXT_SIZE + sizeof(uint32_t) - 1u) / sizeof(uint32_t))

/**
 * @}
 */ /* mcuxClRandomModes_MemoryConsumption */

#endif /* MCUXCLRANDOMMODES_MEMORYCONSUMPTION_H_ */
