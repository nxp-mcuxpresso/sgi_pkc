/*--------------------------------------------------------------------------*/
/* Copyright 2025-2026 NXP                                                  */
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

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCrc.h>

#include <internal/mcuxClCrc_Drv.h>
#include <internal/mcuxClCrc_Internal_Functions.h>
#include <internal/mcuxClCrc_Internal_Constants.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_computeContextCrc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCrc_computeContextCrc(void* pCtx, uint32_t contextSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_computeContextCrc);

    /* Assert context at least contains the crc value */
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(contextSize, 4u, UINT32_MAX);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    uint32_t *pContext = (uint32_t *)pCtx;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_Drv_configureCRC32(MCUXCLCRC_DEFAULT_POLY_32,
                                                                MCUXCLCRC_DEFAULT_SEED_32,
                                                                MCUXCLCRC_DRV_READ_TRANSPOSE_BYTES_NO_BITS  |
                                                                MCUXCLCRC_DRV_WRITE_TRANSPOSE_BYTES_NO_BITS |
                                                                MCUXCLCRC_DRV_BIT_COMPLEMENT_RESULT));

    uint32_t * pContextEnd = pContext + (contextSize / sizeof(uint32_t));
    MCUX_CSSL_DI_RECORD(crcLoop, pContextEnd);

    pContext++; /* skip place for the CRC */
    while( pContext < pContextEnd)
    {
        mcuxClCrc_Drv_writeData32bit(*pContext++);
    }

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    *((uint32_t*) pCtx) = mcuxClCrc_Sfr_readData();
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    MCUX_CSSL_DI_EXPUNGE(crcLoop, pContext);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCrc_computeContextCrc,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Drv_configureCRC32));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCrc_verifyContextCrc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClCrc_verifyContextCrc(mcuxClSession_Handle_t session, void* pCtx, uint32_t contextSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCrc_verifyContextCrc);

    /* Assert context at least contains the crc value */
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(contextSize, 4u, UINT32_MAX);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_VOID()
    uint32_t *pContext = (uint32_t *)pCtx;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_VOID()

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCrc_Drv_configureCRC32(MCUXCLCRC_DEFAULT_POLY_32,
                                                                MCUXCLCRC_DEFAULT_SEED_32,
                                                                MCUXCLCRC_DRV_READ_TRANSPOSE_BYTES_NO_BITS  |
                                                                MCUXCLCRC_DRV_WRITE_TRANSPOSE_BYTES_NO_BITS |
                                                                MCUXCLCRC_DRV_BIT_COMPLEMENT_RESULT));

    uint32_t * pContextEnd = pContext + (contextSize / sizeof(uint32_t));
    MCUX_CSSL_DI_RECORD( crcLoop, pContextEnd);

    pContext++; /* skip place for the CRC */
    while( pContext < pContextEnd)
    {
        mcuxClCrc_Drv_writeData32bit(*pContext++);
    }

    if( *(uint32_t *)pCtx != mcuxClCrc_Sfr_readData())
    {
        MCUXCLSESSION_FAULT(session, MCUXCLCRC_STATUS_FAULT_ATTACK);
    }

    MCUX_CSSL_DI_EXPUNGE(crcLoop, pContext);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClCrc_verifyContextCrc,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCrc_Drv_configureCRC32));
}
