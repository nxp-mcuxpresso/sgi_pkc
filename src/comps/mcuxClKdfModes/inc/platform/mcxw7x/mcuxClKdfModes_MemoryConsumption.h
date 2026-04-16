/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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

/** @file  mcuxClKdfModes_MemoryConsumption.h
 *  @brief Defines the memory consumption for the mcuxClKdfModes component
 *         All work area sizes in bytes are a multiple of CPU wordsize.
 */

#ifndef MCUXCLKDFMODES_MEMORYCONSUMPTION_H_
#define MCUXCLKDFMODES_MEMORYCONSUMPTION_H_

/**
 * @defgroup mcuxClKdfModes_MemoryConsumption mcuxClKdfModes_MemoryConsumption
 * @brief Defines the memory consumption for the mcuxClKdfModes component
 * @ingroup mcuxClKdfModes
 * @{
 */

#define MCUXCLKEY_DERIVATION_MODE_DESCRIPTOR_SIZE                  (16u)
#define MCUXCLKEY_DERIVATION_MODE_DESCRIPTOR_SIZE_IN_WORDS         (MCUXCLKEY_DERIVATION_MODE_DESCRIPTOR_SIZE / sizeof(uint32_t))

#define MCUXCLKEY_DERIVATION_NIST_SP800_108_CPU_WA_SIZE             2048u
#define MCUXCLKEY_DERIVATION_NIST_SP800_108_CPU_WA_SIZE_IN_WORDS    (MCUXCLKEY_DERIVATION_CPU_WA_SIZE / sizeof(uint32_t))
#define MCUXCLKEY_DERIVATION_CM_CPU_WA_SIZE                         MCUXCLKEY_DERIVATION_NIST_SP800_108_CPU_WA_SIZE /* deprecated, use MCUXCLKEY_DERIVATION_NIST_SP800_108_CPU_WA_SIZE instead */
#define MCUXCLKEY_DERIVATION_CM_CPU_WA_SIZE_IN_WORDS                MCUXCLKEY_DERIVATION_NIST_SP800_108_CPU_WA_SIZE_IN_WORDS /* deprecated, use MCUXCLKEY_DERIVATION_NIST_SP800_108_CPU_WA_SIZE_IN_WORDS instead */

#define MCUXCLKEY_DERIVATION_NIST_SP800_56C_CPU_WA_SIZE             3816u
#define MCUXCLKEY_DERIVATION_NIST_SP800_56C_CPU_WA_SIZE_IN_WORDS    (MCUXCLKEY_DERIVATION_NIST_SP800_56C_CPU_WA_SIZE / sizeof(uint32_t))




#define MCUXCLKEY_DERIVATION_HKDF_CPU_WA_SIZE                       2112u
#define MCUXCLKEY_DERIVATION_HKDF_CPU_WA_SIZE_IN_WORDS              (MCUXCLKEY_DERIVATION_HKDF_CPU_WA_SIZE / sizeof(uint32_t))

#define MCUXCLKEY_DERIVATION_PBKDF2_CPU_WA_SIZE                     2212u
#define MCUXCLKEY_DERIVATION_PBKDF2_CPU_WA_SIZE_IN_WORDS            (MCUXCLKEY_DERIVATION_PBKDF2_CPU_WA_SIZE / sizeof(uint32_t))


#define MCUXCLKEY_DERIVATION_CPU_WA_SIZE                            3816u
#define MCUXCLKEY_DERIVATION_CPU_WA_SIZE_IN_WORDS                   (MCUXCLKEY_DERIVATION_CPU_WA_SIZE / sizeof(uint32_t))

/**
 * @}
 */ /* mcuxClKdfModes_MemoryConsumption */

#endif /* MCUXCLKDFMODES_MEMORYCONSUMPTION_H_ */
