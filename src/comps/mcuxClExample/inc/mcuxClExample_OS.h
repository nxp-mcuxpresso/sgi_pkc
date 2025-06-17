/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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

#ifndef MCUXCLEXAMPLE_OS_H_
#define MCUXCLEXAMPLE_OS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Examples.h>

/**
 * @brief Install the interupt handler function in the controller for a specific IRQ number.
 *
 * @param       callback    The interrupt handler function
 * @param       IRQNumber   The IRQ to install the interrupt handler function for
 *
 * @returns void
 *
 * @note This is an abstraction function to illustrate the required OS functionality by the example code.
 *       The implementation most likely needs to be updated to map it to the corresponding functionality
 *       from the target OS that will be used.
*/
static inline void mcuxClExample_OS_Interrupt_Callback_Install(Interrupt_Callback_t callback, uint8_t IRQNumber)
{
  Interrupt_Callback_Install(callback, IRQNumber);
}

/**
 * @brief Uninstall the interupt handler function in the controller for a specific IRQ number.
 *        Currently not implemented because it's not used in the CL.
 *
 * @returns void
 *
 * @note This is an abstraction function to illustrate the required OS functionality by the example code.
 *       The implementation most likely needs to be updated to map it to the corresponding functionality
 *       from the target OS that will be used.
*/
static inline void mcuxClExample_OS_Interrupt_Callback_Uninstall(void)
{
  /* Intended empty */
}

/**
 * @brief Enable a specific IRQ number in the controller.
 *
 * @param       IRQNumber    The IRQ to enable the interrupt for
 *
 * @returns void
 *
 * @note This is an abstraction function to illustrate the required OS functionality by the example code.
 *       The implementation most likely needs to be updated to map it to the corresponding functionality
 *       from the target OS that will be used.
*/
static inline void mcuxClExample_OS_Interrupt_Enable(uint32_t IRQNumber)
{
  S5xy_Enable_IRQ(IRQNumber);
}

/**
 * @brief Disable a specific IRQ number in the controller.
 *
 * @param       IRQNumber    The IRQ to disable the interrupt for
 *
 * @returns void
 *
 * @note This is an abstraction function to illustrate the required OS functionality by the example code.
 *       The implementation most likely needs to be updated to map it to the corresponding functionality
 *       from the target OS that will be used.
*/
static inline void mcuxClExample_OS_Interrupt_Disable(uint32_t IRQNumber)
{
  S5xy_Disable_IRQ(IRQNumber);
}


#endif /* MCUXCLEXAMPLE_OS_H_ */
