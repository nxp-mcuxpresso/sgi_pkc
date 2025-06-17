/*--------------------------------------------------------------------------*/
/* Copyright 2023-2025 NXP                                                  */
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

/** @file  mcuxClAes_SecurityUtils_Sgi.c
 *  @brief Initializing and Deinitializing of the security options */

#include <stddef.h>

#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClAes_Wa.h>
#include <mcuxClSession_Types.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_Functions.h>

#include <internal/mcuxClResource_Internal_Types.h>


