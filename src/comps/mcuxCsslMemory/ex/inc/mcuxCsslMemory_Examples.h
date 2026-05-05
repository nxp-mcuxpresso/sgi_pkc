/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

#ifndef MCUXCSSLMEMORY_EXAMPLES_H_
#define MCUXCSSLMEMORY_EXAMPLES_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MCUXCSSL_MEMORY_EX_FUNCTION(_name) __attribute__((section(".example"))) bool _name(void)

#define MCUXCSSLMEMORY_EX_OK    true
#define MCUXCSSLMEMORY_EX_ERROR false

MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_Compare_example);
MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_Copy_example);
MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_Clear_example);
MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_Set_example);
#ifdef MCUXCL_FEATURE_CSSL_MEMORY_ARM_SECURE_COPY
MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_SecureCopy_example);
#endif
#ifdef MCUXCL_FEATURE_CSSL_MEMORY_ARM_SECURE_XOR
MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_SecureXOR_example);
#endif
MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_SecureSet_example);
#ifdef MCUXCL_FEATURE_CSSL_MEMORY_ARM_SECURE_COMPARE
MCUXCSSL_MEMORY_EX_FUNCTION(mcuxCsslMemory_SecureCompare_example);
#endif

#endif /* MCUXCSSLMEMORY_EXAMPLES_H_ */
