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

#include <mcuxClRandom_Constants.h>
#include <internal/mcuxClRandomModes_Private_ExitGates.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClSession_Internal_Functions.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_cleanupOnExit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_cleanupOnExit(mcuxClSession_Handle_t session)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_cleanupOnExit);

    /* Free CPU WA in Session - SREQI_DRBG_10 */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSession_cleanup_freedWorkareas(session));

    /* Clean up HW memory - SREQI_DRBG_10 */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_cleanUpHW());

    /* Release HW */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_releaseHW(session));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_cleanupOnExit,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup_freedWorkareas),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_cleanUpHW),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_releaseHW));
}

