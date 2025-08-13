/**************************************************************************//**
 * @file     cmsis_ghs.h
 * @brief    CMSIS compiler GHS header file
 * @version  V5.1.0
 * @date     20. December 2018
 ******************************************************************************/
/*
 * Copyright (c) 2009-2018 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __CMSIS_GHS_H
#define __CMSIS_GHS_H

/* ignore some GHS warnings */
//#pragma ghs nowarning 68
//#pragma ghs diagnostic ignored "-Wconversion"
//#pragma ghs diagnostic ignored "-Wunused-parameter"

/* Fallback for __has_builtin */
#ifndef __has_builtin
  #define __has_builtin(x) (0)
#endif

/* CMSIS compiler specific defines */
#ifndef   __ASM
  #define __ASM                                  __asm
#endif
#ifndef   __INLINE
  #define __INLINE                               inline
#endif
#ifndef   __STATIC_INLINE
  #define __STATIC_INLINE                        static inline
#endif
#ifndef   __STATIC_FORCEINLINE                 
  #define __STATIC_FORCEINLINE                   __attribute__((always_inline)) static inline
#endif                                           
#ifndef   __NO_RETURN
  #define __NO_RETURN                            __attribute__((noreturn))
#endif
#ifndef   __USED
  #define __USED                                 __attribute__((used))
#endif
#ifndef   __WEAK
  #define __WEAK                                 __attribute__((weak))
#endif
#ifndef   __PACKED
  #define __PACKED                               __attribute__((packed, aligned(1)))
#endif
#ifndef   __PACKED_STRUCT
  #define __PACKED_STRUCT                        struct __attribute__((packed, aligned(1)))
#endif
#ifndef   __PACKED_UNION
  #define __PACKED_UNION                         union __attribute__((packed, aligned(1)))
#endif
#ifndef   __UNALIGNED_UINT32        /* deprecated */
//  #pragma ghs diagnostic push
//  #pragma ghs diagnostic ignored "-Wpacked"
//  #pragma ghs diagnostic ignored "-Wattributes"
  struct __attribute__((packed)) T_UINT32 { uint32_t v; };
//  #pragma ghs diagnostic pop
  #define __UNALIGNED_UINT32(x)                  (((struct T_UINT32 *)(x))->v)
#endif
#ifndef   __UNALIGNED_UINT16_WRITE
//  #pragma ghs diagnostic push
//  #pragma ghs diagnostic ignored "-Wpacked"
//  #pragma ghs diagnostic ignored "-Wattributes"
  __PACKED_STRUCT T_UINT16_WRITE { uint16_t v; };
//  #pragma ghs diagnostic pop
  #define __UNALIGNED_UINT16_WRITE(addr, val)    (void)((((struct T_UINT16_WRITE *)(void *)(addr))->v) = (val))
#endif
#ifndef   __UNALIGNED_UINT16_READ
//  #pragma ghs diagnostic push
//  #pragma ghs diagnostic ignored "-Wpacked"
//  #pragma ghs diagnostic ignored "-Wattributes"
  __PACKED_STRUCT T_UINT16_READ { uint16_t v; };
//  #pragma ghs diagnostic pop
  #define __UNALIGNED_UINT16_READ(addr)          (((const struct T_UINT16_READ *)(const void *)(addr))->v)
#endif
#ifndef   __UNALIGNED_UINT32_WRITE
//  #pragma ghs diagnostic push
//  #pragma ghs diagnostic ignored "-Wpacked"
//  #pragma ghs diagnostic ignored "-Wattributes"
  __PACKED_STRUCT T_UINT32_WRITE { uint32_t v; };
//  #pragma ghs diagnostic pop
  #define __UNALIGNED_UINT32_WRITE(addr, val)    (void)((((struct T_UINT32_WRITE *)(void *)(addr))->v) = (val))
#endif
#ifndef   __UNALIGNED_UINT32_READ
//  #pragma ghs diagnostic push
//  #pragma ghs diagnostic ignored "-Wpacked"
//  #pragma ghs diagnostic ignored "-Wattributes"
  __PACKED_STRUCT T_UINT32_READ { uint32_t v; };
//  #pragma ghs diagnostic pop
  #define __UNALIGNED_UINT32_READ(addr)          (((const struct T_UINT32_READ *)(const void *)(addr))->v)
#endif
#ifndef   __ALIGNED
  #define __ALIGNED(x)                           __attribute__((aligned(x)))
#endif
#ifndef   __RESTRICT
  #define __RESTRICT                             restrict
#endif


/* ###########################  Core Function Access  ########################### */
/** \ingroup  CMSIS_Core_FunctionInterface
    \defgroup CMSIS_Core_RegAccFunctions CMSIS Core Register Access Functions
  @{
 */

/**
  \brief   Enable IRQ Interrupts
  \details Enables IRQ interrupts by clearing the I-bit in the CPSR.
           Can only be executed in Privileged modes.
 */
__STATIC_FORCEINLINE void __enable_irq(void)
{
  __ASM volatile ("cpsie i" : : : "memory");
}


/**
  \brief   Disable IRQ Interrupts
  \details Disables IRQ interrupts by setting the I-bit in the CPSR.
           Can only be executed in Privileged modes.
 */
__STATIC_FORCEINLINE void __disable_irq(void)
{
  __ASM volatile ("cpsid i" : : : "memory");
}


/**
  \brief   Get Control Register
  \details Returns the content of the Control Register.
  \return               Control Register value
 */
__STATIC_FORCEINLINE uint32_t __get_CONTROL(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, control" : "=r" (result) );
  return(result);
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Get Control Register (non-secure)
  \details Returns the content of the non-secure Control Register when in secure mode.
  \return               non-secure Control Register value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_CONTROL_NS(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, control_ns" : "=r" (result) );
  return(result);
}
#endif


/**
  \brief   Set Control Register
  \details Writes the given value to the Control Register.
  \param [in]    control  Control Register value to set
 */
__STATIC_FORCEINLINE void __set_CONTROL(uint32_t control)
{
  __ASM volatile ("MSR control, %0" : : "r" (control) : "memory");
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Set Control Register (non-secure)
  \details Writes the given value to the non-secure Control Register when in secure state.
  \param [in]    control  Control Register value to set
 */
__STATIC_FORCEINLINE void __TZ_set_CONTROL_NS(uint32_t control)
{
  __ASM volatile ("MSR control_ns, %0" : : "r" (control) : "memory");
}
#endif


/**
  \brief   Get IPSR Register
  \details Returns the content of the IPSR Register.
  \return               IPSR Register value
 */
__STATIC_FORCEINLINE uint32_t __get_IPSR(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, ipsr" : "=r" (result) );
  return(result);
}


/**
  \brief   Get APSR Register
  \details Returns the content of the APSR Register.
  \return               APSR Register value
 */
__STATIC_FORCEINLINE uint32_t __get_APSR(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, apsr" : "=r" (result) );
  return(result);
}


/**
  \brief   Get xPSR Register
  \details Returns the content of the xPSR Register.
  \return               xPSR Register value
 */
__STATIC_FORCEINLINE uint32_t __get_xPSR(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, xpsr" : "=r" (result) );
  return(result);
}


/**
  \brief   Get Process Stack Pointer
  \details Returns the current value of the Process Stack Pointer (PSP).
  \return               PSP Register value
 */
__STATIC_FORCEINLINE uint32_t __get_PSP(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, psp"  : "=r" (result) );
  return(result);
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Get Process Stack Pointer (non-secure)
  \details Returns the current value of the non-secure Process Stack Pointer (PSP) when in secure state.
  \return               PSP Register value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_PSP_NS(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, psp_ns"  : "=r" (result) );
  return(result);
}
#endif


/**
  \brief   Set Process Stack Pointer
  \details Assigns the given value to the Process Stack Pointer (PSP).
  \param [in]    topOfProcStack  Process Stack Pointer value to set
 */
__STATIC_FORCEINLINE void __set_PSP(uint32_t topOfProcStack)
{
  __ASM volatile ("MSR psp, %0" : : "r" (topOfProcStack));
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Set Process Stack Pointer (non-secure)
  \details Assigns the given value to the non-secure Process Stack Pointer (PSP) when in secure state.
  \param [in]    topOfProcStack  Process Stack Pointer value to set
 */
__STATIC_FORCEINLINE void __TZ_set_PSP_NS(uint32_t topOfProcStack)
{
  __ASM volatile ("MSR psp_ns, %0" : : "r" (topOfProcStack));
}
#endif


/**
  \brief   Get Main Stack Pointer
  \details Returns the current value of the Main Stack Pointer (MSP).
  \return               MSP Register value
 */
__STATIC_FORCEINLINE uint32_t __get_MSP(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, msp" : "=r" (result) );
  return(result);
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Get Main Stack Pointer (non-secure)
  \details Returns the current value of the non-secure Main Stack Pointer (MSP) when in secure state.
  \return               MSP Register value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_MSP_NS(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, msp_ns" : "=r" (result) );
  return(result);
}
#endif


/**
  \brief   Set Main Stack Pointer
  \details Assigns the given value to the Main Stack Pointer (MSP).
  \param [in]    topOfMainStack  Main Stack Pointer value to set
 */
__STATIC_FORCEINLINE void __set_MSP(uint32_t topOfMainStack)
{
  __ASM volatile ("MSR msp, %0" : : "r" (topOfMainStack));
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Set Main Stack Pointer (non-secure)
  \details Assigns the given value to the non-secure Main Stack Pointer (MSP) when in secure state.
  \param [in]    topOfMainStack  Main Stack Pointer value to set
 */
__STATIC_FORCEINLINE void __TZ_set_MSP_NS(uint32_t topOfMainStack)
{
  __ASM volatile ("MSR msp_ns, %0" : : "r" (topOfMainStack));
}
#endif


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Get Stack Pointer (non-secure)
  \details Returns the current value of the non-secure Stack Pointer (SP) when in secure state.
  \return               SP Register value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_SP_NS(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, sp_ns" : "=r" (result) );
  return(result);
}


/**
  \brief   Set Stack Pointer (non-secure)
  \details Assigns the given value to the non-secure Stack Pointer (SP) when in secure state.
  \param [in]    topOfStack  Stack Pointer value to set
 */
__STATIC_FORCEINLINE void __TZ_set_SP_NS(uint32_t topOfStack)
{
  __ASM volatile ("MSR sp_ns, %0" : : "r" (topOfStack));
}
#endif


/**
  \brief   Get Priority Mask
  \details Returns the current state of the priority mask bit from the Priority Mask Register.
  \return               Priority Mask value
 */
__STATIC_FORCEINLINE uint32_t __get_PRIMASK(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, primask" : "=r" (result) :: "memory");
  return(result);
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Get Priority Mask (non-secure)
  \details Returns the current state of the non-secure priority mask bit from the Priority Mask Register when in secure state.
  \return               Priority Mask value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_PRIMASK_NS(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, primask_ns" : "=r" (result) :: "memory");
  return(result);
}
#endif


/**
  \brief   Set Priority Mask
  \details Assigns the given value to the Priority Mask Register.
  \param [in]    priMask  Priority Mask
 */
__STATIC_FORCEINLINE void __set_PRIMASK(uint32_t priMask)
{
  __ASM volatile ("MSR primask, %0" : : "r" (priMask) : "memory");
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Set Priority Mask (non-secure)
  \details Assigns the given value to the non-secure Priority Mask Register when in secure state.
  \param [in]    priMask  Priority Mask
 */
__STATIC_FORCEINLINE void __TZ_set_PRIMASK_NS(uint32_t priMask)
{
  __ASM volatile ("MSR primask_ns, %0" : : "r" (priMask) : "memory");
}
#endif


#if ((defined (__ARM_ARCH_7M__      ) && (__ARM_ARCH_7M__      == 1)) || \
     (defined (__ARM_ARCH_7EM__     ) && (__ARM_ARCH_7EM__     == 1)) || \
     (defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1))    )
/**
  \brief   Enable FIQ
  \details Enables FIQ interrupts by clearing the F-bit in the CPSR.
           Can only be executed in Privileged modes.
 */
__STATIC_FORCEINLINE void __enable_fault_irq(void)
{
  __ASM volatile ("cpsie f" : : : "memory");
}


/**
  \brief   Disable FIQ
  \details Disables FIQ interrupts by setting the F-bit in the CPSR.
           Can only be executed in Privileged modes.
 */
__STATIC_FORCEINLINE void __disable_fault_irq(void)
{
  __ASM volatile ("cpsid f" : : : "memory");
}


/**
  \brief   Get Base Priority
  \details Returns the current value of the Base Priority register.
  \return               Base Priority register value
 */
__STATIC_FORCEINLINE uint32_t __get_BASEPRI(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, basepri" : "=r" (result) );
  return(result);
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Get Base Priority (non-secure)
  \details Returns the current value of the non-secure Base Priority register when in secure state.
  \return               Base Priority register value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_BASEPRI_NS(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, basepri_ns" : "=r" (result) );
  return(result);
}
#endif


/**
  \brief   Set Base Priority
  \details Assigns the given value to the Base Priority register.
  \param [in]    basePri  Base Priority value to set
 */
__STATIC_FORCEINLINE void __set_BASEPRI(uint32_t basePri)
{
  __ASM volatile ("MSR basepri, %0" : : "r" (basePri) : "memory");
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Set Base Priority (non-secure)
  \details Assigns the given value to the non-secure Base Priority register when in secure state.
  \param [in]    basePri  Base Priority value to set
 */
__STATIC_FORCEINLINE void __TZ_set_BASEPRI_NS(uint32_t basePri)
{
  __ASM volatile ("MSR basepri_ns, %0" : : "r" (basePri) : "memory");
}
#endif


/**
  \brief   Set Base Priority with condition
  \details Assigns the given value to the Base Priority register only if BASEPRI masking is disabled,
           or the new value increases the BASEPRI priority level.
  \param [in]    basePri  Base Priority value to set
 */
__STATIC_FORCEINLINE void __set_BASEPRI_MAX(uint32_t basePri)
{
  __ASM volatile ("MSR basepri_max, %0" : : "r" (basePri) : "memory");
}


/**
  \brief   Get Fault Mask
  \details Returns the current value of the Fault Mask register.
  \return               Fault Mask register value
 */
__STATIC_FORCEINLINE uint32_t __get_FAULTMASK(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, faultmask" : "=r" (result) );
  return(result);
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Get Fault Mask (non-secure)
  \details Returns the current value of the non-secure Fault Mask register when in secure state.
  \return               Fault Mask register value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_FAULTMASK_NS(void)
{
  uint32_t result;

  __ASM volatile ("MRS %0, faultmask_ns" : "=r" (result) );
  return(result);
}
#endif


/**
  \brief   Set Fault Mask
  \details Assigns the given value to the Fault Mask register.
  \param [in]    faultMask  Fault Mask value to set
 */
__STATIC_FORCEINLINE void __set_FAULTMASK(uint32_t faultMask)
{
  __ASM volatile ("MSR faultmask, %0" : : "r" (faultMask) : "memory");
}


#if (defined (__ARM_FEATURE_CMSE ) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Set Fault Mask (non-secure)
  \details Assigns the given value to the non-secure Fault Mask register when in secure state.
  \param [in]    faultMask  Fault Mask value to set
 */
__STATIC_FORCEINLINE void __TZ_set_FAULTMASK_NS(uint32_t faultMask)
{
  __ASM volatile ("MSR faultmask_ns, %0" : : "r" (faultMask) : "memory");
}
#endif

#endif /* ((defined (__ARM_ARCH_7M__      ) && (__ARM_ARCH_7M__      == 1)) || \
           (defined (__ARM_ARCH_7EM__     ) && (__ARM_ARCH_7EM__     == 1)) || \
           (defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1))    ) */


#if ((defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)) || \
     (defined (__ARM_ARCH_8M_BASE__ ) && (__ARM_ARCH_8M_BASE__ == 1))    )

/**
  \brief   Get Process Stack Pointer Limit
  Devices without ARMv8-M Main Extensions (i.e. Cortex-M23) lack the non-secure
  Stack Pointer Limit register hence zero is returned always in non-secure
  mode.
  
  \details Returns the current value of the Process Stack Pointer Limit (PSPLIM).
  \return               PSPLIM Register value
 */
__STATIC_FORCEINLINE uint32_t __get_PSPLIM(void)
{
#if (!(defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)) && \
    (!defined (__ARM_FEATURE_CMSE) || (__ARM_FEATURE_CMSE < 3)))
    // without main extensions, the non-secure PSPLIM is RAZ/WI
  return 0U;
#else
  uint32_t result;
  __ASM volatile ("MRS %0, psplim"  : "=r" (result) );
  return result;
#endif
}

#if (defined (__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3))
/**
  \brief   Get Process Stack Pointer Limit (non-secure)
  Devices without ARMv8-M Main Extensions (i.e. Cortex-M23) lack the non-secure
  Stack Pointer Limit register hence zero is returned always.

  \details Returns the current value of the non-secure Process Stack Pointer Limit (PSPLIM) when in secure state.
  \return               PSPLIM Register value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_PSPLIM_NS(void)
{
#if (!(defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)))
  // without main extensions, the non-secure PSPLIM is RAZ/WI
  return 0U;
#else
  uint32_t result;
  __ASM volatile ("MRS %0, psplim_ns"  : "=r" (result) );
  return result;
#endif
}
#endif


/**
  \brief   Set Process Stack Pointer Limit
  Devices without ARMv8-M Main Extensions (i.e. Cortex-M23) lack the non-secure
  Stack Pointer Limit register hence the write is silently ignored in non-secure
  mode.
  
  \details Assigns the given value to the Process Stack Pointer Limit (PSPLIM).
  \param [in]    ProcStackPtrLimit  Process Stack Pointer Limit value to set
 */
__STATIC_FORCEINLINE void __set_PSPLIM(uint32_t ProcStackPtrLimit)
{
#if (!(defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)) && \
    (!defined (__ARM_FEATURE_CMSE) || (__ARM_FEATURE_CMSE < 3)))
  // without main extensions, the non-secure PSPLIM is RAZ/WI
  (void)ProcStackPtrLimit;
#else
  __ASM volatile ("MSR psplim, %0" : : "r" (ProcStackPtrLimit));
#endif
}


#if (defined (__ARM_FEATURE_CMSE  ) && (__ARM_FEATURE_CMSE   == 3))
/**
  \brief   Set Process Stack Pointer (non-secure)
  Devices without ARMv8-M Main Extensions (i.e. Cortex-M23) lack the non-secure
  Stack Pointer Limit register hence the write is silently ignored.

  \details Assigns the given value to the non-secure Process Stack Pointer Limit (PSPLIM) when in secure state.
  \param [in]    ProcStackPtrLimit  Process Stack Pointer Limit value to set
 */
__STATIC_FORCEINLINE void __TZ_set_PSPLIM_NS(uint32_t ProcStackPtrLimit)
{
#if (!(defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)))
  // without main extensions, the non-secure PSPLIM is RAZ/WI
  (void)ProcStackPtrLimit;
#else
  __ASM volatile ("MSR psplim_ns, %0\n" : : "r" (ProcStackPtrLimit));
#endif
}
#endif


/**
  \brief   Get Main Stack Pointer Limit
  Devices without ARMv8-M Main Extensions (i.e. Cortex-M23) lack the non-secure
  Stack Pointer Limit register hence zero is returned always in non-secure
  mode.

  \details Returns the current value of the Main Stack Pointer Limit (MSPLIM).
  \return               MSPLIM Register value
 */
__STATIC_FORCEINLINE uint32_t __get_MSPLIM(void)
{
#if (!(defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)) && \
    (!defined (__ARM_FEATURE_CMSE) || (__ARM_FEATURE_CMSE < 3)))
  // without main extensions, the non-secure MSPLIM is RAZ/WI
  return 0U;
#else
  uint32_t result;
  __ASM volatile ("MRS %0, msplim" : "=r" (result) );
  return result;
#endif
}


#if (defined (__ARM_FEATURE_CMSE  ) && (__ARM_FEATURE_CMSE   == 3))
/**
  \brief   Get Main Stack Pointer Limit (non-secure)
  Devices without ARMv8-M Main Extensions (i.e. Cortex-M23) lack the non-secure
  Stack Pointer Limit register hence zero is returned always.

  \details Returns the current value of the non-secure Main Stack Pointer Limit(MSPLIM) when in secure state.
  \return               MSPLIM Register value
 */
__STATIC_FORCEINLINE uint32_t __TZ_get_MSPLIM_NS(void)
{
#if (!(defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)))
  // without main extensions, the non-secure MSPLIM is RAZ/WI
  return 0U;
#else
  uint32_t result;
  __ASM volatile ("MRS %0, msplim_ns" : "=r" (result) );
  return result;
#endif
}
#endif


/**
  \brief   Set Main Stack Pointer Limit
  Devices without ARMv8-M Main Extensions (i.e. Cortex-M23) lack the non-secure
  Stack Pointer Limit register hence the write is silently ignored in non-secure
  mode.

  \details Assigns the given value to the Main Stack Pointer Limit (MSPLIM).
  \param [in]    MainStackPtrLimit  Main Stack Pointer Limit value to set
 */
__STATIC_FORCEINLINE void __set_MSPLIM(uint32_t MainStackPtrLimit)
{
#if (!(defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)) && \
    (!defined (__ARM_FEATURE_CMSE) || (__ARM_FEATURE_CMSE < 3)))
  // without main extensions, the non-secure MSPLIM is RAZ/WI
  (void)MainStackPtrLimit;
#else
  __ASM volatile ("MSR msplim, %0" : : "r" (MainStackPtrLimit));
#endif
}


#if (defined (__ARM_FEATURE_CMSE  ) && (__ARM_FEATURE_CMSE   == 3))
/**
  \brief   Set Main Stack Pointer Limit (non-secure)
  Devices without ARMv8-M Main Extensions (i.e. Cortex-M23) lack the non-secure
  Stack Pointer Limit register hence the write is silently ignored.

  \details Assigns the given value to the non-secure Main Stack Pointer Limit (MSPLIM) when in secure state.
  \param [in]    MainStackPtrLimit  Main Stack Pointer value to set
 */
__STATIC_FORCEINLINE void __TZ_set_MSPLIM_NS(uint32_t MainStackPtrLimit)
{
#if (!(defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)))
  // without main extensions, the non-secure MSPLIM is RAZ/WI
  (void)MainStackPtrLimit;
#else
  __ASM volatile ("MSR msplim_ns, %0" : : "r" (MainStackPtrLimit));
#endif
}
#endif

#endif /* ((defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1)) || \
           (defined (__ARM_ARCH_8M_BASE__ ) && (__ARM_ARCH_8M_BASE__ == 1))    ) */


/**
  \brief   Get FPSCR
  \details Returns the current value of the Floating Point Status/Control register.
  \return               Floating Point Status/Control register value
 */
__STATIC_FORCEINLINE uint32_t __get_FPSCR(void)
{
#if ((defined (__FPU_PRESENT) && (__FPU_PRESENT == 1U)) && \
     (defined (__FPU_USED   ) && (__FPU_USED    == 1U))     )
#if __has_builtin(__builtin_arm_get_fpscr) 
// Re-enable using built-in when GCC has been fixed
// || (__GNUC__ > 7) || (__GNUC__ == 7 && __GNUC_MINOR__ >= 2)
  /* see https://gcc.gnu.org/ml/gcc-patches/2017-04/msg00443.html */
  return __builtin_arm_get_fpscr();
#else
  uint32_t result;

  __ASM volatile ("VMRS %0, fpscr" : "=r" (result) );
  return(result);
#endif
#else
  return(0U);
#endif
}


/**
  \brief   Set FPSCR
  \details Assigns the given value to the Floating Point Status/Control register.
  \param [in]    fpscr  Floating Point Status/Control value to set
 */
__STATIC_FORCEINLINE void __set_FPSCR(uint32_t fpscr)
{
#if ((defined (__FPU_PRESENT) && (__FPU_PRESENT == 1U)) && \
     (defined (__FPU_USED   ) && (__FPU_USED    == 1U))     )
#if __has_builtin(__builtin_arm_set_fpscr)
// Re-enable using built-in when GCC has been fixed
// || (__GNUC__ > 7) || (__GNUC__ == 7 && __GNUC_MINOR__ >= 2)
  /* see https://gcc.gnu.org/ml/gcc-patches/2017-04/msg00443.html */
  __builtin_arm_set_fpscr(fpscr);
#else
  __ASM volatile ("VMSR fpscr, %0" : : "r" (fpscr) : "vfpcc", "memory");
#endif
#else
  (void)fpscr;
#endif
}


/*@} end of CMSIS_Core_RegAccFunctions */


/* ##########################  Core Instruction Access  ######################### */
/** \defgroup CMSIS_Core_InstructionInterface CMSIS Core Instruction Interface
  Access to dedicated instructions
  @{
*/

#include <arm_ghs.h>

/* Define macros for porting to both thumb1 and thumb2.
 * For thumb1, use low register (r0-r7), specified by constraint "l"
 * Otherwise, use general registers, specified by constraint "r" */
#if defined (__thumb__) && !defined (__thumb2__)
#define __CMSIS_GHS_OUT_REG(r) "=l" (r)
#define __CMSIS_GHS_RW_REG(r) "+l" (r)
#define __CMSIS_GHS_USE_REG(r) "l" (r)
#else
#define __CMSIS_GHS_OUT_REG(r) "=r" (r)
#define __CMSIS_GHS_RW_REG(r) "+r" (r)
#define __CMSIS_GHS_USE_REG(r) "r" (r)
#endif

/**
  \brief   Rotate Right in unsigned value (32 bit)
  \details Rotate Right (immediate) provides the value of the contents of a register rotated by a variable number of bits.
  \param [in]    op1  Value to rotate
  \param [in]    op2  Number of Bits to rotate
  \return               Rotated value
 */
__STATIC_FORCEINLINE uint32_t __ROR(uint32_t op1, uint32_t op2)
{
  op2 %= 32U;
  if (op2 == 0U)
  {
    return op1;
  }
  return (op1 >> op2) | (op1 << (32U - op2));
}


/**
  \brief   Count leading zeros
  \details Counts the number of leading zeros of a data value.
  \param [in]  value  Value to count the leading zeros
  \return             number of leading zeros in value
 */
__STATIC_FORCEINLINE uint8_t __CLZ_internal(uint32_t value)
{
  /* Even though __builtin_clz produces a CLZ instruction on ARM, formally
     __builtin_clz(0) is undefined behaviour, so handle this case specially.
     This guarantees ARM-compatible results if happening to compile on a non-ARM
     target, and ensures the compiler doesn't decide to activate any
     optimisations using the logic "value was passed to __builtin_clz, so it
     is non-zero".
     ARM GCC 7.3 and possibly earlier will optimise this test away, leaving a
     single CLZ instruction.
   */
  if (value == 0U)
  {
    return 32U;
  }
  return __CLZ32(value);
}
#define __CLZ __CLZ_internal

//#pragma ghs endnowarning 68


#endif /* __CMSIS_GHS_H */
