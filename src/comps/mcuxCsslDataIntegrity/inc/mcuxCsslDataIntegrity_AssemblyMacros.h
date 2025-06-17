/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * @file  mcuxCsslDataIntegrity_AssemblyMacros.h
 * @brief Assembly macros for the data integrity mechanism
 */

#ifndef MCUXCSSLDATAINTEGRITY_ASSEMBLYMACROS_H_
#define MCUXCSSLDATAINTEGRITY_ASSEMBLYMACROS_H_


/**
 * \addtogroup mcuxCsslIMPL MCUX CSSL -- Implementations
 *
 * \defgroup mcuxCsslDataIntegrity_Asm Data Integrity: Assembly implementation
 * \brief Assembly implementation of the data integrity mechanism.
 * \ingroup mcuxCsslIMPL
 */

/**
 * \def MCUX_CSSL_DI_ASM_BASE
 * \brief DI SFR base address for SCM hardware
 * \ingroup mcuxCsslDataIntegrity_Asm
 */
#define MCUX_CSSL_DI_ASM_BASE()

/**
 * \def MCUX_CSSL_DI_ASM_INIT_BASE
 * \brief Assembly macro: Initialize the base address for the data integrity.
 *        This should be performed before calling other assembly macros MCUX_CSSL_DI_ASM_RECORD and MCUX_CSSL_DI_ASM_EXPUNGE.
 *        Usage in assembly: "MCUX_CSSL_DI_ASM_INIT_BASE baseReg"
 * \ingroup mcuxCsslDataIntegrity_Asm
 *
 * \param baseReg    Register that will be assigned the base address.
 */
#define MCUX_CSSL_DI_ASM_INIT_BASE()

/**
 * \def MCUX_CSSL_DI_ASM_INIT_BASE_COND
 * \brief Assembly macro: conditionally initialize the base address for the data integrity.
 *        This macro assumes the register (baseReg) contains the base address of the other HW SFR,
 *        %hi(addressOtherHw). If the base addresses (DI and the other hardware) are different,
 *        this macro will initialize the base address for DI; otherwise, this macro does nothing.
 *        Using this macro can avoid initializing register with the same base address.
 *        Usage in assembly: "MCUX_CSSL_DI_ASM_INIT_BASE_COND baseReg, addressOtherHw"
 * \ingroup mcuxCsslDataIntegrity_Asm
 *
 * \param baseReg    Register that will be assigned the base address.
 * \param addressOtherHw  a constant, which is an address of another hardware SFR
 */
#define MCUX_CSSL_DI_ASM_INIT_BASE_COND()

/**
 * \def MCUX_CSSL_DI_ASM_VALUE
 * \brief Assembly macro: Retrieves the current data integrity value.
 *        Usage in assembly: "MCUX_CSSL_DI_ASM_VALUE baseReg, valueReg"
 * \ingroup mcuxCsslDataIntegrity_Asm
 *
 * \param baseReg    Register that contains the base address for DI, previously initialized with MCUX_CSSL_DI_ASM_INIT_BASE.
 * \param valueReg   Register to store the DI value.
 */
#define MCUX_CSSL_DI_ASM_VALUE()

/**
 * \def MCUX_CSSL_DI_ASM_REF_VALUE
 * \brief Assembly macro: Retrieves the current data integrity reference value.
 *        Usage in assembly: "MCUX_CSSL_DI_ASM_REF_VALUE baseReg, valueReg"
 * \ingroup mcuxCsslDataIntegrity_Asm
 *
 * \param baseReg    Register that contains the base address for DI, previously initialized with MCUX_CSSL_DI_ASM_INIT_BASE.
 * \param valueReg   Register to store the reference DI value.
 */
#define MCUX_CSSL_DI_ASM_REF_VALUE()

/**
 * \def MCUX_CSSL_DI_ASM_WRITE_REF
 * \brief Assembly macro: Writes the data integrity reference value.
 *        Usage in assembly: "MCUX_CSSL_DI_ASM_WRITE_REF baseReg, valueReg"
 * \ingroup mcuxCsslDataIntegrity_Asm
 *
 * \param baseReg    Register that contains the base address for DI, previously initialized with MCUX_CSSL_DI_ASM_INIT_BASE.
 * \param valueReg   Register that contains the reference DI value.
 */
#define MCUX_CSSL_DI_ASM_WRITE_REF()

/**
 * \def MCUX_CSSL_DI_ASM_RECORD
 * \brief Assembly macro: Record the value for data integrity checking.
 *        Usage in assembly: "MCUX_CSSL_DI_ASM_RECORD baseReg, valueReg"
 * \ingroup mcuxCsslDataIntegrity_Asm
 *
 * \param baseReg    Register that contains the base address for DI, previously initialized with MCUX_CSSL_DI_ASM_INIT_BASE.
 * \param valueReg   Register that contains the value which needs to be recorded.
 */
#define MCUX_CSSL_DI_ASM_RECORD()

/**
 * \def MCUX_CSSL_DI_RECORD_IMPL
 * \brief Assembly macro: Expunge the record for value.
 *        Usage in assembly: "MCUX_CSSL_DI_ASM_EXPUNGE baseReg, valueReg"
 * \ingroup mcuxCsslDataIntegrity_Asm
 *
 * \param baseReg    Register that contains the base address for DI, previously initialized with MCUX_CSSL_DI_ASM_INIT_BASE.
 * \param valueReg   Register that contains the expected value that was recorded.
 */
#define MCUX_CSSL_DI_ASM_EXPUNGE()


#endif /* MCUXCSSLDATAINTEGRITY_ASSEMBLYMACROS_H_ */
