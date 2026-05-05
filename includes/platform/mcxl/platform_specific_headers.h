 /*--------------------------------------------------------------------------*/
 /* Copyright 2021-2026 NXP                                                  */
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
