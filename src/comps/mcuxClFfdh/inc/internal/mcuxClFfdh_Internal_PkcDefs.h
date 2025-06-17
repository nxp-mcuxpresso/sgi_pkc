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

/**
 * @file  mcuxClFfdh_Internal_PkcDefs.h
 * @brief Internal definitions of the mcuxClFfdh component
 */

#ifndef MCUXCLFFDH_INTERNAL_PKCDEFS_H_
#define MCUXCLFFDH_INTERNAL_PKCDEFS_H_

#include <mcuxClFfdh_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/****************************************************************************/
/* Indices of operands in PKC workarea and UPTR table for the mcuxClFfdh     */
/****************************************************************************/
#define FFDH_UPTRTINDEX_P               (0u) ///< UPTR virtual table index for buffer P
#define FFDH_UPTRTINDEX_PFULL           (1u) ///< UPTR table index for P'|P buffer
#define FFDH_UPTRTINDEX_BASE            (2u) ///< UPTR table index for base buffer
#define FFDH_UPTRTINDEX_EXP             (3u) ///< UPTR table index for exponent buffer
#define FFDH_UPTRTINDEX_T1              (4u) ///< UPTR table index for temp 1 buffer
#define FFDH_UPTRTINDEX_T2              (5u) ///< UPTR table index for temp 2 buffer
#define FFDH_UPTRTINDEX_T3              (6u) ///< UPTR table index for temp 3 buffer
#define FFDH_UPTRTINDEX_T4              (7u) ///< UPTR table index for temp 4 buffer
#define FFDH_UPTRTINDEX_T5              (8u) ///< UPTR table index for temp 5 buffer
#define FFDH_UPTRTINDEX_T6              (9u) ///< UPTR table index for temp 6 buffer
#define FFDH_UPTRT_COUNT                (10u) ///< UPTR table size of function mcuxClFfdh key agreement

#define FFDH_NO_OF_VIRTUALS   (FFDH_UPTRTINDEX_PFULL) ///< UPTR table size of function mcuxClFfdh key agreement
#define FFDH_NO_OF_BUFFERS    (FFDH_UPTRT_COUNT - FFDH_NO_OF_VIRTUALS) ///< UPTR table size of function mcuxClFfdh key agreement


/*******************************************************************************/
/* Defines to control placement of temporary exponentiation buffer (pExpTemp)  */
/*******************************************************************************/
/*  Define which informs if all secure exponentiation buffers can fit into the PKC RAM for given prime length.
    Size is hardcoded since particular group may be unavailable due to feature flag choice. */
#define FFDH_EXPTMP_FAME_RAM_ONLY_MAX_LENGTH (6144U / 8U)


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLFFDH_INTERNAL_PKCDEFS_H_ */


