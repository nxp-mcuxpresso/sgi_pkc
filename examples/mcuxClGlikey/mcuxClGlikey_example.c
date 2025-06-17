/*--------------------------------------------------------------------------*/
/* Copyright 2022-2025 NXP                                                  */
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

#include <platform_specific_headers.h> // Defines for GLIKEY IP, e.g. base addresses
#include <mcuxClToolchain.h> // memory segment definitions
#include <mcuxClGlikey.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Examples.h>


#define EXAMPLE_CRITICAL_VALUE 0x1234u
#define MCUXCLGLIKEY_CODEWORD_STEP3_PROTECTED MCUXCLGLIKEY_CODEWORD_STEP3 ^ EXAMPLE_CRITICAL_VALUE

MCUXCLEXAMPLE_FUNCTION(mcuxClGlikey_example)
{
#if defined(CPU_MIMXRT798SGAWA_cm33_core0) || defined(CPU_MIMXRT798SGFOA_cm33_core0)
    mcuxClGlikey_BaseAddress_t *base = (mcuxClGlikey_BaseAddress_t *)GLIKEY3_BASEADDRESS;
    uint32_t index = 0x7u;
#else
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("The GLIKEY0_BASEADDRESS is aligned")
    mcuxClGlikey_BaseAddress_t *base = (mcuxClGlikey_BaseAddress_t *)GLIKEY0_BASEADDRESS;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    uint32_t index = 0x1u;
#endif /* defined(CPU_MIMXRT798SGAWA_cm33_core0) || defined(CPU_MIMXRT798SGFOA_cm33_core0) */

    /* Since start FSM state is WR_EN, a soft reset moves it to LOCKED state, such that we can enter INIT state in mcuxClGlikey_StartEnable */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status0, sync_reset_token, mcuxClGlikey_SyncReset(base));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_SyncReset) != sync_reset_token) || MCUXCLGLIKEY_STATUS_OK != status0)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status1, is_locked_token, mcuxClGlikey_IsLocked(base));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_IsLocked) != is_locked_token) || MCUXCLGLIKEY_STATUS_NOT_LOCKED != status1)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status2, start_enable_token, mcuxClGlikey_StartEnable(base, index));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_StartEnable) != start_enable_token) || MCUXCLGLIKEY_STATUS_OK != status2)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    //perform tests to assure enabling of the indexed SFR can continue
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status3, continue_enable1_token, mcuxClGlikey_ContinueEnable(base, MCUXCLGLIKEY_CODEWORD_STEP1));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_ContinueEnable) != continue_enable1_token) || MCUXCLGLIKEY_STATUS_OK != status3)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status4, continue_enable2_token, mcuxClGlikey_ContinueEnable(base, MCUXCLGLIKEY_CODEWORD_STEP2));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_ContinueEnable) != continue_enable2_token) || MCUXCLGLIKEY_STATUS_OK != status4)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t example_check_value = EXAMPLE_CRITICAL_VALUE; // should depend on some calculation
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status5, continue_enable3_token,
        mcuxClGlikey_ContinueEnable(base, MCUXCLGLIKEY_CODEWORD_STEP3_PROTECTED ^ example_check_value));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_ContinueEnable) != continue_enable3_token) || MCUXCLGLIKEY_STATUS_OK != status5)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

#ifdef GLIKEY_STEPS_8
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status6, continue_enable4_token, mcuxClGlikey_ContinueEnable(base, MCUXCLGLIKEY_CODEWORD_STEP4));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_ContinueEnable) != continue_enable4_token) || MCUXCLGLIKEY_STATUS_OK != status6)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status7, continue_enable5_token, mcuxClGlikey_ContinueEnable(base, MCUXCLGLIKEY_CODEWORD_STEP5));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_ContinueEnable) != continue_enable5_token) || MCUXCLGLIKEY_STATUS_OK != status7)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status8, continue_enable6_token, mcuxClGlikey_ContinueEnable(base, MCUXCLGLIKEY_CODEWORD_STEP6));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_ContinueEnable) != continue_enable6_token) || MCUXCLGLIKEY_STATUS_OK != status8)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status9, continue_enable7_token, mcuxClGlikey_ContinueEnable(base, MCUXCLGLIKEY_CODEWORD_STEP7));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_ContinueEnable) != continue_enable7_token) || MCUXCLGLIKEY_STATUS_OK != status9)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
#endif

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status10, continue_enable8_token,mcuxClGlikey_ContinueEnable(base, MCUXCLGLIKEY_CODEWORD_STEP_EN));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_ContinueEnable) != continue_enable8_token) || MCUXCLGLIKEY_STATUS_OK != status10)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status11, end_token, mcuxClGlikey_EndOperation(base));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClGlikey_EndOperation) != end_token) || MCUXCLGLIKEY_STATUS_OK != status11)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    return MCUXCLEXAMPLE_STATUS_OK;
}
