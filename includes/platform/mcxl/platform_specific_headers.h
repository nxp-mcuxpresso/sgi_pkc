/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
/*--------------------------------------------------------------------------*/
 
 #ifndef PLATFORM_SPECIFIC_HEADERS_H_ 
 #define PLATFORM_SPECIFIC_HEADERS_H_ 
 #pragma once
 
 #include "mcuxClConfig.h"
 #include "mcuxCsslAnalysis.h"
 
 MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_HEADER()
 #include "ip_platform.h" 
 #include "MCXL255_cm33.h" 
 #include "MCXL255_cm33_COMMON.h" 
 #include "MCXL255_cm33_features.h" 
 #include "system_MCXL255_cm33.h" 
 #include "PERI_ADC.h" 
 #include "PERI_AHBSC.h" 
 #include "PERI_AOI.h" 
 #include "PERI_ATX.h" 
 #include "PERI_CDOG.h" 
 #include "PERI_CGU.h" 
 #include "PERI_CMC.h" 
 #include "PERI_CRC.h" 
 #include "PERI_CTIMER.h" 
 #include "PERI_DEBUGMAILBOX.h" 
 #include "PERI_DMA.h" 
 #include "PERI_ERM.h" 
 #include "PERI_FMC.h" 
 #include "PERI_FMU.h" 
 #include "PERI_FMUTEST.h" 
 #include "PERI_FREQME.h" 
 #include "PERI_GLIKEY.h" 
 #include "PERI_GPIO.h" 
 #include "PERI_INPUTMUX_AON.h" 
 #include "PERI_INPUTMUX_MAIN.h" 
 #include "PERI_KPP.h" 
 #include "PERI_LPACMP.h" 
 #include "PERI_LPADC.h" 
 #include "PERI_LPCMP.h" 
 #include "PERI_LPI2C.h" 
 #include "PERI_LPSPI.h" 
 #include "PERI_LPTMR.h" 
 #include "PERI_LPUART.h" 
 #include "PERI_MRCC.h" 
 #include "PERI_MU.h" 
 #include "PERI_OSTIMER.h" 
 #include "PERI_PKC.h" 
 #include "PERI_PMU.h" 
 #include "PERI_PORT.h" 
 #include "PERI_RTC.h" 
 #include "PERI_SCG.h" 
 #include "PERI_SGI.h" 
 #include "PERI_SGLCD_CONTROL.h" 
 #include "PERI_SGLCD_FAULT_DETECT.h" 
 #include "PERI_SMM.h" 
 #include "PERI_SYSCON.h" 
 #include "PERI_SYSCON_AON.h" 
 #include "PERI_TMR.h" 
 #include "PERI_TRDC.h" 
 #include "PERI_TRNG.h" 
 #include "PERI_UDF.h" 
 #include "PERI_UTICK.h" 
 #include "PERI_WUU.h" 
 #include "PERI_WWDT.h" 
 MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_HEADER()
 
 #endif /*PLATFORM_SPECIFIC_HEADERS_H_*/ 
