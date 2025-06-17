/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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

#ifndef MCUX_CSSL_ASSEMBLY_H_
#define MCUX_CSSL_ASSEMBLY_H_

#include <mcuxCsslCPreProcessor.h>

/* for armclang */
#if defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
#define MCUX_CSSL_ASM_LABEL(name) \
  name:

#define MCUX_CSSL_ASM_FILE_START() \
  .syntax unified

#define MCUX_CSSL_ASM_FILE_END()

#define MCUX_CSSL_ASM_FUNC_ALIGNMENT() \
  .align 2

#define MCUX_CSSL_ASM_FUNC_SECTION(name) \
  .section MCUX_CSSL_CPP_CAT(.text.,name)

#define MCUX_CSSL_ASM_FUNC_SYMBOL(name) \
  .type name,"function"

#define MCUX_CSSL_ASM_FUNC_START(name) \
  MCUX_CSSL_ASM_LABEL(name)

#define MCUX_CSSL_ASM_FUNC_END(name)


/* for llvm */
#elif defined ( __clang__ )
#define MCUX_CSSL_ASM_LABEL(name) \
  name:

#define MCUX_CSSL_ASM_FILE_START() \
  .syntax unified

#define MCUX_CSSL_ASM_FILE_END()

#define MCUX_CSSL_ASM_FUNC_ALIGNMENT() \
  .align 2

#define MCUX_CSSL_ASM_FUNC_SECTION(name) \
  .section MCUX_CSSL_CPP_CAT(.text.,name)

#define MCUX_CSSL_ASM_FUNC_SYMBOL(name) \
  .type name,"function"

#define MCUX_CSSL_ASM_FUNC_START(name) \
  MCUX_CSSL_ASM_LABEL(name)

#define MCUX_CSSL_ASM_FUNC_END(name)

/* using the gcc toolchain file for both gcc and armgcc */
#elif defined ( __GNUC__ )
#define MCUX_CSSL_ASM_LABEL(name) \
  name:

#define MCUX_CSSL_ASM_FILE_START() \
  .syntax unified

#define MCUX_CSSL_ASM_FILE_END()

#define MCUX_CSSL_ASM_FUNC_ALIGNMENT() \
  .align 2

#define MCUX_CSSL_ASM_FUNC_SECTION(name) \
  .section MCUX_CSSL_CPP_CAT(.text.,name)

#define MCUX_CSSL_ASM_FUNC_SYMBOL(name) \
  .type name,"function"

#define MCUX_CSSL_ASM_FUNC_START(name) \
  MCUX_CSSL_ASM_LABEL(name)

#define MCUX_CSSL_ASM_FUNC_END(name)

/* for armcc compiler */
#elif defined ( __CC_ARM )
#define MCUX_CSSL_ASM_FILE_START()

#define MCUX_CSSL_ASM_FILE_END() \
  MCUX_CSSL_CPP_EMPTY()    END

#define MCUX_CSSL_ASM_LABEL(name) \
  name

#define MCUX_CSSL_ASM_FUNC_SECTION(name) \
  MCUX_CSSL_CPP_EMPTY()    AREA MCUX_CSSL_CPP_CAT3(|i.,name,|), CODE, ALIGN=4

#define MCUX_CSSL_ASM_FUNC_ALIGNMENT() \
  MCUX_CSSL_CPP_EMPTY()    ALIGN

#define MCUX_CSSL_ASM_FUNC_SYMBOL(name) \
  MCUX_CSSL_CPP_EMPTY()    EXPORT name

#define MCUX_CSSL_ASM_FUNC_START(name) \
  MCUX_CSSL_ASM_LABEL(name) FUNCTION

#define MCUX_CSSL_ASM_FUNC_END(name) \
  MCUX_CSSL_CPP_EMPTY()    ENDFUNC

/* for ghs compiler */
#elif defined ( __ghs__ )
#define MCUX_CSSL_ASM_LABEL(name) \
  name:

#define MCUX_CSSL_ASM_FILE_START()

#define MCUX_CSSL_ASM_FILE_END()

#define MCUX_CSSL_ASM_FUNC_ALIGNMENT() \
  .align 2

#define MCUX_CSSL_ASM_FUNC_SECTION(name) \
  .section MCUX_CSSL_CPP_CAT(.text.,name)

#define MCUX_CSSL_ASM_FUNC_SYMBOL(name) \
  .type name, $function

#define MCUX_CSSL_ASM_FUNC_START(name) \
  MCUX_CSSL_ASM_LABEL(name)

#define MCUX_CSSL_ASM_FUNC_END(name)

/* for iar compiler */
#elif defined ( __ICCARM__ )
#define MCUX_CSSL_ASM_LABEL(name) \
/* TODO CLNS-16812 implement macros for IAR */
#else
#error Unsupported assembler
#endif

#endif /* MCUX_CSSL_ASSEMBLY_H_ */
