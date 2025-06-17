/*--------------------------------------------------------------------------*/
/* Copyright 2021-2025 NXP                                                  */
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

#include <mcuxClAes_Constants.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <mcuxClSgi_Constants.h>
#include <mcuxClSgi_Types.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Sfr_RegBank.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxCsslAnalysis.h>
#include <internal/mcuxClDma_Drv.h>
#include <mcuxClMemory_Constants.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>

#include <internal/mcuxClResource_Internal_Types.h>

#include <mcuxClBuffer.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal_Functions.h>

#include <mcuxClCore_Toolchain.h>
#include <mcuxClCore_Macros.h>

/*****************************************************
 * utilHash Constants
 *****************************************************/

static const uint32_t mcuxClSgi_Utils_iv_sha_512_224[] = {
    0xC8373D8CU, 0xA24D5419U,
    0x6699E173U, 0xD6D4DC89U,
    0xAEB7FA1DU, 0x829CFF32U,
    0x14D59D67U, 0xCF9F2F58U,
    0x692B6D0FU, 0xA84DD47BU,
    0x736FE377U, 0x4289C404U,
    0xA8859D3FU, 0xC8361D6AU,
    0xADE61211U, 0xA192D691U
};

static const uint32_t mcuxClSgi_Utils_iv_sha_512_256[] = {
    0x94213122U, 0x2CF72BFCU,
    0xA35F559FU, 0xC2644CC8U,
    0x6BB89323U, 0x51B1536FU,
    0x19773896U, 0xBDEA4059U,
    0xE23E2896U, 0xE3FF8EA8U,
    0x251E5EBEU, 0x92398653U,
    0xFC99012BU, 0xAAB8852CU,
    0xDC2DB70EU, 0xA22CC581U
};


/*****************************************************
 * utilHash Functions
 *****************************************************/

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_initSha224, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha224(const uint32_t *pIV, uint32_t mode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_initSha224);

    if(MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV == mode)
    {
        /* Configure SHA2-224 in auto mode using standard IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_224_AUTOMODE_LOADDATA_USESTANDARDIV));
    }
    else if(MCUXCLSGI_UTILS_AUTO_MODE_LOAD_IV == mode)
    {
        /* Configure SHA2-224, loading a special IV/state in auto mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_224_AUTOMODE_LOADIV));

        /* Start SGI SHA2-224 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Load IV/state to FIFO */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(pIV, MCUXCLSGI_DRV_STATE_SIZE_SHA2_224));

        /* Trigger stop (indicate that IV loading has finished) */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-224, loading data in auto mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_224_AUTOMODE_LOADDATA_USELOADEDIV));
    }
    else if(MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV == mode)
    {
        /* Configure SHA2-224 in normal mode using standard IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_224_NORMALMODE_LOADDATA_USESTANDARDIV));
    }
    else
    {
        /* Configure SHA2-224, loading a special IV/state in normal mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_224_NORMALMODE_LOADIV));

        /* Load IV to DATIN and KEY register banks */
        MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_load256BitBlock_params, MCUXCLSGI_DRV_DATIN0_OFFSET);
        MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_load256BitBlock_params, pIV);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load256BitBlock));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load256BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, (const uint8_t*) pIV));

        /* Start SGI SHA2-224 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-224, loading data in normal mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_224_NORMALMODE_LOADDATA_USELOADEDIV));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_initSha224);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_initSha256, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha256(const uint32_t *pIV, uint32_t mode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_initSha256);

    if(MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV == mode)
    {
        /* Configure SHA2-256 in auto mode using standard IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_256_AUTOMODE_LOADDATA_USESTANDARDIV));
    }
    else if(MCUXCLSGI_UTILS_AUTO_MODE_LOAD_IV == mode)
    {
        /* Configure SHA2-256, loading a special IV/state in auto mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_256_AUTOMODE_LOADIV));

        /* Start SGI SHA2-256 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Load IV/state to FIFO */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(pIV, MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_256));

        /* Trigger stop (indicate that IV loading has finished) */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-256, loading data in auto mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_256_AUTOMODE_LOADDATA_USELOADEDIV));
    }
    else if(MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV == mode)
    {
        /* Configure SHA2-256 in normal mode using standard IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_256_NORMALMODE_LOADDATA_USESTANDARDIV));
    }
    else
    {
        /* Configure SHA2-256, loading a special IV/state in normal mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_256_NORMALMODE_LOADIV));

        /* Load IV to DATIN and KEY register banks */
        MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_load256BitBlock_params, MCUXCLSGI_DRV_DATIN0_OFFSET);
        MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_load256BitBlock_params, pIV);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load256BitBlock));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load256BitBlock(MCUXCLSGI_DRV_DATIN0_OFFSET, (const uint8_t*) pIV));

        /* Start SGI SHA2-256 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-256, loading data in normal mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_256_NORMALMODE_LOADDATA_USELOADEDIV));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_initSha256);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_initSha384, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha384(const uint32_t *pIV, uint32_t mode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_initSha384);

    if(MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV == mode)
    {
        /* Configure SHA2-384 in auto mode using standard IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_384_AUTOMODE_LOADDATA_USESTANDARDIV));
    }
    else if(MCUXCLSGI_UTILS_AUTO_MODE_LOAD_IV == mode)
    {
        /* Configure SHA2-384, loading a special IV/state in auto mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_384_AUTOMODE_LOADIV));

        /* Start SGI SHA2-384 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Load IV/state to FIFO */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(pIV, MCUXCLSGI_DRV_STATE_SIZE_SHA2_384));

        /* Trigger stop (indicate that IV loading has finished) */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-384, loading data in auto mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_384_AUTOMODE_LOADDATA_USELOADEDIV));
    }
    else if(MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV == mode)
    {
        /* Configure SHA2-384 in normal mode using standard IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_384_NORMALMODE_LOADDATA_USESTANDARDIV));
    }
    else
    {
        /* Configure SHA2-384, loading a special IV/state in normal mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_384_NORMALMODE_LOADIV));

        /* Load IV to DATIN and KEY register banks */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load512BitBlock(pIV));

        /* Start SGI SHA2-384 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-384, loading data in normal mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_384_NORMALMODE_LOADDATA_USELOADEDIV));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_initSha384);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_initSha512, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha512(const uint32_t *pIV, uint32_t mode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_initSha512);

    if(MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV == mode)
    {
        /* Configure SHA2-512 in auto mode using standard IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_AUTOMODE_LOADDATA_USESTANDARDIV));
    }
    else if(MCUXCLSGI_UTILS_AUTO_MODE_LOAD_IV == mode)
    {
        /* Configure SHA2-512, loading a special IV/state in auto mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_AUTOMODE_LOADIV));

        /* Start SGI SHA2-512 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Load IV/state to FIFO */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(pIV, MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_512));

        /* Trigger stop (indicate that IV loading has finished) */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-512, loading data in auto mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_AUTOMODE_LOADDATA_USELOADEDIV));
    }
    else if(MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV == mode)
    {
        /* Configure SHA2-512 in normal mode using standard IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_NORMALMODE_LOADDATA_USESTANDARDIV));
    }
    else
    {
        /* Configure SHA2-512, loading a special IV/state in normal mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_NORMALMODE_LOADIV));

        /* Load IV to DATIN and KEY register banks */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load512BitBlock(pIV));

        /* Start SGI SHA2-512 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-512, loading data in normal mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_NORMALMODE_LOADDATA_USELOADEDIV));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_initSha512);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_initSha512_224, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha512_224(const uint32_t *pIV, uint32_t mode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_initSha512_224);

    if((MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV == mode) || (MCUXCLSGI_UTILS_AUTO_MODE_LOAD_IV == mode))
    {
        /* Configure SHA2-512, loading a special IV/state in auto mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_AUTOMODE_LOADIV));

        /* Start SGI SHA2-512 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        if(MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV == mode)
        {
            /* Load IV/state to FIFO */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(mcuxClSgi_Utils_iv_sha_512_224, MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_512));
        }
        else
        {
            /* Load IV/state to FIFO */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(pIV, MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_512));
        }

        /* Trigger stop (indicate that IV loading has finished) */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-512, loading data in auto mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_AUTOMODE_LOADDATA_USELOADEDIV));

    }
    else
    {
        /* Configure SHA2-512, loading a special IV/state in normal mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_NORMALMODE_LOADIV));

        if(MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV == mode)
        {
            /* Load IV to DATIN and KEY register banks */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load512BitBlock(mcuxClSgi_Utils_iv_sha_512_224));
        }
        else
        {
            /* Load IV to DATIN and KEY register banks */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load512BitBlock(pIV));
        }

        /* Start SGI SHA2-512 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-512, loading data in normal mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_NORMALMODE_LOADDATA_USELOADEDIV));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_initSha512_224);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_initSha512_256, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha512_256(const uint32_t *pIV, uint32_t mode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_initSha512_256);

    if((MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV == mode) || (MCUXCLSGI_UTILS_AUTO_MODE_LOAD_IV == mode))
    {
        /* Configure SHA2-512, loading a special IV/state in auto mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_AUTOMODE_LOADIV));

        /* Start SGI SHA2-512 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        if(MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV == mode)
        {
            /* Load IV/state to FIFO */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(mcuxClSgi_Utils_iv_sha_512_256, MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_512));
        }
        else
        {
            /* Load IV/state to FIFO */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadFifo));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_loadFifo(pIV, MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_512));
        }

        /* Trigger stop (indicate that IV loading has finished) */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopSha2());

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-512, loading data in auto mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_AUTOMODE_LOADDATA_USELOADEDIV));

    }
    else
    {
        /* Configure SHA2-512, loading a special IV/state in normal mode */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_NORMALMODE_LOADIV));

        if(MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV == mode)
        {
            /* Load IV to DATIN and KEY register banks */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load512BitBlock(mcuxClSgi_Utils_iv_sha_512_256));
        }
        else
        {
            /* Load IV to DATIN and KEY register banks */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load512BitBlock));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load512BitBlock(pIV));
        }

        /* Start SGI SHA2-512 processing */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_START_SHA2));

        /* Wait until SGI has loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

        /* Configure SHA2-512, loading data in normal mode, using the already loaded IV */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureSha2));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureSha2(MCUXCLSGI_DRV_CONFIG_SHA2_512_NORMALMODE_LOADDATA_USELOADEDIV));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_initSha512_256);
}

/* Using this function for data copy from user input to SGI implements SREQI_BCIPHER_1 */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_load128BitBlock_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load128BitBlock_buffer(uint32_t sgisfrDatOffset, mcuxCl_InputBuffer_t dataBuf, uint32_t offset)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_load128BitBlock_buffer);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(sgisfrDatOffset, 0U, sizeof(SGI_STRUCT_NAME), MCUXCLSGI_STATUS_FAULT);

    //Read data from buffer and put into SGI
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_word));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_word(
        dataBuf, offset, (uint8_t*)mcuxClSgi_Sfr_getAddr(sgisfrDatOffset), 16U)
    );

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_load128BitBlock_buffer);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_load128BitBlock)
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load128BitBlock(uint32_t sgisfrDatOffset, const uint8_t *pData)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_load128BitBlock);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(sgisfrDatOffset, 0U, MCUXCLSGI_DRV_DATIN2_OFFSET, )
    uint8_t *pRegAddr = (uint8_t*)mcuxClSgi_Drv_getAddr(sgisfrDatOffset);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pRegAddr, pData, 16U));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_load128BitBlock);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_load_notFull128Block_buffer)
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load_notFull128Block_buffer(uint32_t sgisfrDatOffset, mcuxCl_InputBuffer_t pData, uint32_t len, uint8_t *pTempBuff)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_load_notFull128Block_buffer);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(sgisfrDatOffset, 0U, MCUXCLSGI_DRV_DATIN2_OFFSET, MCUXCLSGI_STATUS_ERROR)

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(pData, 0U, pTempBuff, len));

    /* Balance multiple EXPUNGEs of the input params - SGI offset is recorded by caller */
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, pTempBuff);
    MCUX_CSSL_DI_RECORD(mcuxClBuffer_read, 16U);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(sgisfrDatOffset, (uint8_t *)pTempBuff));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_load_notFull128Block_buffer);
}

/* Using this function for data copy from SGI to user output implements SREQI_BCIPHER_1 */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_store128BitBlock_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_store128BitBlock_buffer(mcuxClSession_Handle_t session, uint32_t sgisfrDatOffset, mcuxCl_Buffer_t outBuf, uint32_t offset)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_store128BitBlock_buffer);

    /* Write to buffer from SGI, src pointer is calculated from sgisfrDatOffset */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write_word));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write_word(
      outBuf, offset, (uint8_t*)mcuxClSgi_Sfr_getAddr(sgisfrDatOffset), 16U)
    );

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_store128BitBlock_buffer);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_storeMasked128BitBlock_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storeMasked128BitBlock_buffer(mcuxClSession_Handle_t session, uint32_t sgisfrDatOffset, mcuxCl_Buffer_t outBuf, uint32_t offset, const uint32_t* pXorMask)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_storeMasked128BitBlock_buffer);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(offset, 0U, MCUXCLSGI_DRV_DATOUT_OFFSET, MCUXCLSGI_STATUS_ERROR);

    MCUX_CSSL_FP_FUNCTION_CALL(ctrl2backup, mcuxClSgi_Drv_enableXorWrite());
    uint32_t* pRegAddr = mcuxClSgi_Sfr_getAddr(sgisfrDatOffset);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int((uint8_t *)pRegAddr, (const uint8_t *)pXorMask, 16U));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write_word));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write_word(outBuf,
                                                        offset,
                                                        (const uint8_t *)pRegAddr,
                                                        16U));

    /* Disable XOR-masking */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_setCtrl2(ctrl2backup));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_storeMasked128BitBlock_buffer,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableXorWrite),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setCtrl2));
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_store128BitBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_store128BitBlock(uint32_t sgisfrDatOffset, uint8_t *pOut)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_store128BitBlock);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(sgisfrDatOffset, 0U, MCUXCLSGI_DRV_DATIN2_OFFSET, MCUXCLSGI_STATUS_FAULT)
    uint8_t *pRegAddr = (uint8_t*)mcuxClSgi_Drv_getAddr(sgisfrDatOffset);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pOut, pRegAddr, 16U));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_store128BitBlock,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_load256BitBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load256BitBlock(uint32_t sgisfrDatOffset, const uint8_t *pData)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_load256BitBlock);

    uint8_t *pRegAddr = (uint8_t*)mcuxClSgi_Drv_getAddr(sgisfrDatOffset);
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pRegAddr, pData, 32U));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_load256BitBlock,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_load512BitBlock, mcuxClSgi_Utils_loadInternalHashBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load512BitBlock(const uint32_t *pData)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_load512BitBlock);

    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 0U, pData[0]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 4U, pData[1]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 8U, pData[2]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 12U, pData[3]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 16U, pData[4]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 20U, pData[5]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 24U, pData[6]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 28U, pData[7]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 32U, pData[8]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 36U, pData[9]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 40U, pData[10]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 44U, pData[11]);
#if( MCUXCLSGI_SFR_DATIN_CNT > 12U )   /* if the DATIN3 bank is available */
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 48U, pData[12]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 52U, pData[13]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 56U, pData[14]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 60U, pData[15]);
#else
    mcuxClSgi_Drv_loadKeyWord(0, pData[12]);
    mcuxClSgi_Drv_loadKeyWord(1, pData[13]);
    mcuxClSgi_Drv_loadKeyWord(2, pData[14]);
    mcuxClSgi_Drv_loadKeyWord(3, pData[15]);
#endif /* MCUXCLSGI_SFR_DATIN_CNT */

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_load512BitBlock);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_load512BitBlock_buffer, mcuxClSgi_Utils_loadExternalHashBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load512BitBlock_buffer(mcuxClSession_Handle_t session, mcuxCl_InputBuffer_t dataBuf, uint32_t offset)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_load512BitBlock_buffer);

#if( MCUXCLSGI_SFR_DATIN_CNT > 12U )   /* if the DATIN3 bank is available */

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_word));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_word(
    dataBuf, offset, (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET), 64U)
  );
#else
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_word));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_word(
    dataBuf, offset, (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET), 48U)
  );

  /* All addresses are 32 bits and the input buffer has to hold at least 512 bits */
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(offset, 0U, UINT32_MAX - 48U)
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_word));

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_word(
    dataBuf, offset + 48U, (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_KEY0_OFFSET), 16U)
  );
#endif
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_load512BitBlock_buffer);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_load1024BitBlock, mcuxClSgi_Utils_loadInternalHashBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load1024BitBlock(const uint32_t *pData)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_load1024BitBlock);

    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 0U, pData[0]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 4U, pData[1]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 8U, pData[2]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 12U, pData[3]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 16U, pData[4]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 20U, pData[5]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 24U, pData[6]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 28U, pData[7]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 32U, pData[8]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 36U, pData[9]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 40U, pData[10]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 44U, pData[11]);
#if( MCUXCLSGI_SFR_DATIN_CNT > 12U )   /* if the DATIN3 bank is available */
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 48U, pData[12]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 52U, pData[13]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 56U, pData[14]);
    mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + 60U, pData[15]);
    mcuxClSgi_Drv_loadKeyWord(0, pData[16]);
    mcuxClSgi_Drv_loadKeyWord(1, pData[17]);
    mcuxClSgi_Drv_loadKeyWord(2, pData[18]);
    mcuxClSgi_Drv_loadKeyWord(3, pData[19]);
    mcuxClSgi_Drv_loadKeyWord(4, pData[20]);
    mcuxClSgi_Drv_loadKeyWord(5, pData[21]);
    mcuxClSgi_Drv_loadKeyWord(6, pData[22]);
    mcuxClSgi_Drv_loadKeyWord(7, pData[23]);
    mcuxClSgi_Drv_loadKeyWord(8, pData[24]);
    mcuxClSgi_Drv_loadKeyWord(9, pData[25]);
    mcuxClSgi_Drv_loadKeyWord(10, pData[26]);
    mcuxClSgi_Drv_loadKeyWord(11, pData[27]);
    mcuxClSgi_Drv_loadKeyWord(12, pData[28]);
    mcuxClSgi_Drv_loadKeyWord(13, pData[29]);
    mcuxClSgi_Drv_loadKeyWord(14, pData[30]);
    mcuxClSgi_Drv_loadKeyWord(15, pData[31]);
#else
    mcuxClSgi_Drv_loadKeyWord(0, pData[12]);
    mcuxClSgi_Drv_loadKeyWord(1, pData[13]);
    mcuxClSgi_Drv_loadKeyWord(2, pData[14]);
    mcuxClSgi_Drv_loadKeyWord(3, pData[15]);
    mcuxClSgi_Drv_loadKeyWord(4, pData[16]);
    mcuxClSgi_Drv_loadKeyWord(5, pData[17]);
    mcuxClSgi_Drv_loadKeyWord(6, pData[18]);
    mcuxClSgi_Drv_loadKeyWord(7, pData[19]);
    mcuxClSgi_Drv_loadKeyWord(8, pData[20]);
    mcuxClSgi_Drv_loadKeyWord(9, pData[21]);
    mcuxClSgi_Drv_loadKeyWord(10, pData[22]);
    mcuxClSgi_Drv_loadKeyWord(11, pData[23]);
    mcuxClSgi_Drv_loadKeyWord(12, pData[24]);
    mcuxClSgi_Drv_loadKeyWord(13, pData[25]);
    mcuxClSgi_Drv_loadKeyWord(14, pData[26]);
    mcuxClSgi_Drv_loadKeyWord(15, pData[27]);
    mcuxClSgi_Drv_loadKeyWord(16, pData[28]);
    mcuxClSgi_Drv_loadKeyWord(17, pData[29]);
    mcuxClSgi_Drv_loadKeyWord(18, pData[30]);
    mcuxClSgi_Drv_loadKeyWord(19, pData[31]);
#endif /* MCUXCLSGI_SFR_DATIN_CNT */

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_load1024BitBlock);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_load1024BitBlock_buffer, mcuxClSgi_Utils_loadExternalHashBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load1024BitBlock_buffer(mcuxClSession_Handle_t session, mcuxCl_InputBuffer_t dataBuf, uint32_t offset)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_load1024BitBlock_buffer);

#if(MCUXCLSGI_SFR_DATIN_CNT > 12U)  /* if the DATIN3 bank is available */
    /* All addresses are 32 bits and the input buffer has to hold at least 1024 bits */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_word));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_word(
      dataBuf, offset, (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET), 128U)
    );
#else
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_word));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_word(
      dataBuf, offset, (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET), 48U)
    );

    /* All addresses are 32 bits and the input buffer has to hold at least 1024 bits */
    MCUX_CSSL_ANALYSIS_COVERITY_ASSERT(offset, 0U, UINT32_MAX - 48U, MCUXCLSGI_STATUS_ERROR)

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read_word));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read_word(
      dataBuf, offset + 48U, (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_KEY0_OFFSET), 80U)
    );
#endif /* MCUXCLSGI_SFR_DATIN_CNT */

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_load1024BitBlock_buffer);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI(uint32_t sgisfrDatOffset, mcuxCl_Buffer_t outBuf, uint32_t offset, const uint32_t* pXorMask)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI);

    MCUX_CSSL_DI_RECORD(bufferReadDI, 2U * (uint32_t) mcuxClSgi_Sfr_getAddr(sgisfrDatOffset));
    MCUX_CSSL_DI_RECORD(bufferReadDI, 2U * 16U);
    MCUX_CSSL_DI_RECORD(bufferReadDI, pXorMask);
    MCUX_CSSL_DI_RECORD(bufferReadDI, outBuf);
    MCUX_CSSL_DI_RECORD(bufferReadDI, offset);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_loadHashBlock_buffer_recordDI)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_loadHashBlock_buffer_recordDI(mcuxCl_InputBuffer_t dataBuf, uint32_t offset, uint32_t blockSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_loadHashBlock_buffer_recordDI);

    MCUX_CSSL_DI_RECORD(loadHashBlockBalancing, mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET));
#if(MCUXCLSGI_SFR_DATIN_CNT > 12U)  /* if the DATIN3 bank is available, we perform only one copy */
    MCUX_CSSL_DI_RECORD(loadHashBlockBalancing, dataBuf);
    MCUX_CSSL_DI_RECORD(loadHashBlockBalancing, offset);
    MCUX_CSSL_DI_RECORD(loadHashBlockBalancing, blockSize);
#else
    MCUX_CSSL_DI_RECORD(loadHashBlockBalancing, 2U * dataBuf);
    MCUX_CSSL_DI_RECORD(loadHashBlockBalancing, (2U * offset) + 48U);
    MCUX_CSSL_DI_RECORD(loadHashBlockBalancing, blockSize);
    MCUX_CSSL_DI_RECORD(loadHashBlockBalancing, mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_KEY0_OFFSET));
#endif /* MCUXCLSGI_SFR_DATIN_CNT */

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_loadHashBlock_buffer_recordDI);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_loadFifo)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_loadFifo(const uint32_t *pData, uint32_t length)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_loadFifo);

    /* Load data to FIFO word-wise */
    for(uint32_t i = 0U; i < (length / sizeof(uint32_t)); i++)
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_loadFifo));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_loadFifo(pData[i]));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_loadFifo);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_storePartialHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storePartialHash(uint32_t *pOutput, uint32_t length)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_storePartialHash);

    uint32_t sha2_mode = mcuxClSgi_Sfr_readSha2Ctrl() & MCUXCLSGI_DRV_CONFIG_SHA2_MASK;

    uint32_t digestSize = 0xFFFFU;

    if(MCUXCLSGI_DRV_CONFIG_SHA2_224 == sha2_mode)
    {
        digestSize = MCUXCLSGI_DRV_STATE_SIZE_SHA2_224;
    }
    else if(MCUXCLSGI_DRV_CONFIG_SHA2_256 == sha2_mode)
    {
        digestSize = MCUXCLSGI_DRV_STATE_SIZE_SHA2_256;
    }
    else if(MCUXCLSGI_DRV_CONFIG_SHA2_384 == sha2_mode)
    {
        digestSize = MCUXCLSGI_DRV_STATE_SIZE_SHA2_384;
    }
    else
    {
        digestSize = MCUXCLSGI_DRV_STATE_SIZE_SHA2_512;
    }

    if(digestSize < length)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_storePartialHash);
    }

    /* Wait until SGI has finished */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    for(uint32_t i = 0U; i < (length / sizeof(uint32_t)); i++)
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Increment within valid pOutput address")
        *pOutput++ = mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + (4U * (i & 3U)));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        if((0x3U == (i & 0x3U)) && ((i + 1U) < (length / sizeof(uint32_t))))
        {
            /* Trigger new output after 4 words are read, if length not yet reached */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_triggerOutput));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_triggerOutput());
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());
        }
    }

    /* Make sure to read the full DATOUT register, perform dummy reads */
    uint32_t processedWords = MCUXCLCORE_NUM_OF_WORDS_CEIL(4U, length);
    for(uint32_t i = (processedWords % 4U); i < 4U; i++)
    {
        (void) mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + (4U*i));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_storePartialHash);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_storeHashResult)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storeHashResult(mcuxClSession_Handle_t session, mcuxCl_Buffer_t pOutput, uint32_t length)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_storeHashResult);

    uint32_t sha2_mode = mcuxClSgi_Sfr_readSha2Ctrl() & MCUXCLSGI_DRV_CONFIG_SHA2_MASK;

    uint32_t digestSize = 0xFFFFU;

    if(MCUXCLSGI_DRV_CONFIG_SHA2_224 == sha2_mode)
    {
        digestSize = MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_224;
    }
    else if(MCUXCLSGI_DRV_CONFIG_SHA2_256 == sha2_mode)
    {
        digestSize = MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_256;
    }
    else if(MCUXCLSGI_DRV_CONFIG_SHA2_384 == sha2_mode)
    {
        digestSize = MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_384;
    }
    else
    {
        digestSize = MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_512;
    }

    if(digestSize < length)
    {
        MCUXCLSESSION_ERROR(session, MCUXCLSGI_STATUS_ERROR);
    }

    /* Wait until SGI has finished */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    uint32_t offset = 0U;
    uint32_t remainingLength = length;

    /* Process the result in 16 bytes' multiple */
    while (16U <= remainingLength)
    {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write_word));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write_word(
          pOutput, offset, (const uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET), 16U)
      );

      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("offset can't exceed UINT32_MAX.")
      offset += 16U;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

      remainingLength -= 16U;
      if(remainingLength > 0U)
      {
        /* Trigger new output after 4 words are read, if length not yet reached */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_triggerOutput));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_triggerOutput());
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());
        }
    }

    /* Process the hash size is not a multiple of 16 */
    if (0U < remainingLength)
    {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write_word));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write_word(
        pOutput,
        offset,
        (const uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET),
        remainingLength
      ));

      /* Make sure to read the full DATOUT register, perform dummy reads */
      for(uint32_t i = (remainingLength / 4U); i < 4U; i++)
      {
        (void)mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + (4U * i));
      }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_storeHashResult);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_storeHashResult_recordDI)
MCUX_CSSL_ANALYSIS_START_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is defined indeed")
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storeHashResult_recordDI(mcuxCl_Buffer_t pOutput, uint32_t length)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_SYMBOL_DECLARED_MORE_THAN_ONCE()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_storeHashResult_recordDI);

    MCUX_CSSL_DI_RECORD(storeHashResultBalancing, length);
    /* There are ceil(length / 16) iterations in mcuxClSgi_Utils_storeHashResult that perform mcuxClBuffer_write_word. */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(length, 0U, MCUXCLSGI_DRV_DIGEST_SIZE_SHA2_512, /* void */)
    uint32_t iterations = MCUXCLCORE_NUM_OF_WORDS_CEIL(16U, length);
    MCUX_CSSL_DI_RECORD(storeHashResultBalancing, iterations * (uint32_t) pOutput);
    MCUX_CSSL_DI_RECORD(storeHashResultBalancing, iterations * (uint32_t) mcuxClSgi_Sfr_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET));
    /* Sum of offsets is 0+16+32+48+...16*(iterations-1) = 16 * ((iterations -1) * iterations) / 2 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("values used for SC balancing which supports unsigned overflow behaviour")
    uint32_t sumOfOffsets = 8U * ((iterations - 1U) * iterations);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_DI_RECORD(storeHashResultBalancing, sumOfOffsets);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_storeHashResult_recordDI);
}


/** Configure the SGI in AUTO mode. Use two DMA channels to tranfer data to/from SGI.
    Use SGI/DMA Handshake signals to coordinate the communication. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_startAutoModeWithHandshakes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_startAutoModeWithHandshakes(
  uint32_t operation,
  uint32_t enableOutputHandshake)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_startAutoModeWithHandshakes);

  /* Configure and start the SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(operation));

  /* Enable the handshake signal(s) - will start the DMA input channel to start writing data to the SGI DATIN */
  if(MCUXCLSGI_UTILS_OUTPUT_HANDSHAKE_ENABLE == enableOutputHandshake)
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableDmaHandshakes));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableDmaHandshakes());
  }
  else
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableInputDmaHandshake));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_enableInputDmaHandshake());
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_startAutoModeWithHandshakes);
}

/** Stop and disable the SGI AUTO mode, disable handshakes for DMA channel in the SGI/DMA/SCM */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_stopAutoModeWithDmaInputHandshakes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_stopAutoModeWithDmaInputHandshakes(
  mcuxClSession_Channel_t inputChannel)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_stopAutoModeWithDmaInputHandshakes);

  /* AUTO mode needs to be stopped by software */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopAndDisableAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopAndDisableAutoMode());

  /* Disable DMA handshakes in the SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableDmaHandshakes));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableDmaHandshakes());

  /* Disable DMA handshaking */
  mcuxClDma_Sfr_setSrcSelect(inputChannel, MCUXCLDMA_DRV_HWREQ_SRC_DISABLED);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_stopAutoModeWithDmaInputHandshakes);
}

/** Stop and disable the SGI AUTO mode, disable handshakes for both DMA channels in the SGI/DMA/SCM */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes(
  mcuxClSession_Channel_t inputChannel,
  mcuxClSession_Channel_t outputChannel)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes);

  /* AUTO mode needs to be stopped by software */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_stopAndDisableAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_stopAndDisableAutoMode());

  /* Disable DMA handshakes in the SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_disableDmaHandshakes));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_disableDmaHandshakes());

  /* Disable DMA handshaking */
  mcuxClDma_Sfr_setSrcSelect(inputChannel, MCUXCLDMA_DRV_HWREQ_SRC_DISABLED);
  mcuxClDma_Sfr_setSrcSelect(outputChannel, MCUXCLDMA_DRV_HWREQ_SRC_DISABLED);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_Request)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_Request(mcuxClSession_Handle_t session, mcuxClResource_HwStatus_t hwStatusOption)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_Request);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_request));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_request(session, MCUXCLRESOURCE_HWID_SGI, hwStatusOption, NULL, 0U));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_Request);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_Uninit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_Uninit(mcuxClSession_Handle_t session)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_Uninit);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClResource_release));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClResource_release(session->pResourceCtx, MCUXCLRESOURCE_HWID_SGI));

MCUX_CSSL_ANALYSIS_START_SUPPRESS_RETURN_CODE_NOT_CHECKED("Return code is checked in every call to this function")
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_close));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_close(session));
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_RETURN_CODE_NOT_CHECKED()

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_Uninit);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_copySfrMasked)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_copySfrMasked(uint32_t *pDst, const uint32_t *pSrc, uint32_t length, uint32_t sfrSeed)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_copySfrMasked);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_enableMasking));
  MCUX_CSSL_FP_FUNCTION_CALL(ctrl2Backup, mcuxClSgi_Drv_enableMasking(MCUXCLSGI_DRV_MASKING_SFR, sfrSeed));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int((uint8_t*)pDst, (const uint8_t*)pSrc, length));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_setCtrl2));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_setCtrl2(ctrl2Backup));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_copySfrMasked);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_decrement128Bit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_decrement128Bit(uint32_t srcSfrDatOffset, uint32_t dstSfrDatOffset)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_decrement128Bit);
    uint8_t* pSrc = (uint8_t*)mcuxClSgi_Drv_getAddr(srcSfrDatOffset);
    uint8_t* pDst = (uint8_t*)mcuxClSgi_Drv_getAddr(dstSfrDatOffset);

    MCUX_CSSL_DI_RECORD(memCopy, pDst);
    MCUX_CSSL_DI_RECORD(memCopy, pSrc);
    MCUX_CSSL_DI_RECORD(memCopy, 16U);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pDst, pSrc, 16U));

    const uint32_t wordSize = 4U;
    const uint32_t leastWordOffset = 12U;
    uint32_t wordOffset = 0U;
    uint32_t dataWord = 0U;

    while ((wordOffset <= leastWordOffset) && (dataWord == 0U))
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Calculated offset doesn't wrap.")
        uint32_t dataOffset = dstSfrDatOffset + leastWordOffset - wordOffset;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

        dataWord = mcuxClSgi_Drv_storeWord(dataOffset);

        if (dataWord == 0U)
        {
            mcuxClSgi_Drv_loadWord(dataOffset, 0xffffffffU);
        }
        else
        {
            const uint32_t decreasedWord = mcuxCl_Core_Swap32(mcuxCl_Core_Swap32(dataWord) - 1U);
            mcuxClSgi_Drv_loadWord(dataOffset, decreasedWord);
        }

      wordOffset += wordSize;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_decrement128Bit);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_keyUnwrapRfc3394)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_keyUnwrapRfc3394(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_keyUnwrapRfc3394);

  /* Determine the auto mode for key wrap depending on the size of the key material */
  mcuxClKey_Size_t plainKeyMaterialSize = mcuxClKey_getSize(key);
  uint32_t keyWrapConfig = 0U;
  if(MCUXCLAES_AES128_KEY_SIZE == plainKeyMaterialSize)
  {
    keyWrapConfig = MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_KEYWRAP_128;
  }
  else if(MCUXCLAES_AES256_KEY_SIZE == plainKeyMaterialSize)
  {
    keyWrapConfig = MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_KEYWRAP_256;
  }
  else
  {
    /* Aes-192 is not supported */
    MCUXCLSESSION_ERROR(session, MCUXCLSGI_STATUS_KEYSIZE_NOT_SUPPORTED);
  }

  /* The key-wrapping key (kwk) is stored as a pointer to a full key descriptor in the key handle's auxData buffer. */
  const mcuxClKey_Descriptor_t *kwk = mcuxClKey_getKeyDescriptorFromAuxData(key);

  /* Configure the SGI: Perform a key unwrap with the associated kwk */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(keyWrapConfig));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_CTRL_KEY_UNWRAP | mcuxClSgi_getKeyConf(kwk)));

  /* Load the wrapped key material to DATIN0/DATIN1(/DATIN2) after the operation was started */
  uint8_t *pDatin0 = (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_SFR_DATIN0_OFFSET);
  uint8_t *pWrappedKeyData = mcuxClKey_getKeyData(key);
  uint32_t wrappedKeySize = plainKeyMaterialSize + MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, pDatin0);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, pWrappedKeyData);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, wrappedKeySize);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pDatin0, pWrappedKeyData, wrappedKeySize));

  /* Wait for the SGI to finish the key wrap */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

  /* Disable the AUTO mode */
  mcuxClSgi_Drv_resetAutoMode();

  /* The unwrapped key material is now in the key register bank that is fixed in hardware
   * for each platform. See MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP.
   * Even if the unwrapping was invalid, the invalid unwrapped material will be placed in this
   * key register. */

  /* Check for unwrapping errors - the SGI checks internally whether the RFC3394 IV is correct */
  uint32_t sgiStatus = mcuxClSgi_Sfr_readStatus();
  if(MCUXCLSGI_SFR_STATUS_HAS_KEY_UNWRAP_ERROR(sgiStatus))
  {
    MCUXCLSESSION_ERROR(session, MCUXCLSGI_STATUS_UNWRAP_ERROR);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_keyUnwrapRfc3394);
}

/**
 * @brief This function performs RFC3394 key wrapping with the SGI.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_keyWrapRfc3394)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_keyWrapRfc3394(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  const uint8_t* pKeyMaterial,
  const uint32_t* pSfrSeed
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_keyWrapRfc3394);

  /* Determine the auto mode for key wrap depending on the size of the key material */
  mcuxClKey_Size_t plainKeyMaterialSize = mcuxClKey_getSize(key);
  uint32_t keyWrapConfig = 0U;
  if(MCUXCLAES_AES128_KEY_SIZE == plainKeyMaterialSize)
  {
    keyWrapConfig = MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_KEYWRAP_128;
  }
  else if(MCUXCLAES_AES256_KEY_SIZE == plainKeyMaterialSize)
  {
    keyWrapConfig = MCUXCLSGI_DRV_CONFIG_AUTO_MODE_ENABLE_KEYWRAP_256;
  }
  else
  {
    /* Aes-192 is not supported */
    MCUXCLSESSION_ERROR(session, MCUXCLSGI_STATUS_KEYSIZE_NOT_SUPPORTED);
  }

  /* Initialize the SGI */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));

  /* The key-wrapping key (kwk) is stored as a pointer to a full key descriptor in the key handle's auxData buffer. */
  const mcuxClKey_Descriptor_t *kwk = mcuxClKey_getKeyDescriptorFromAuxData(key);

  /* Configure the SGI: Perform a key unwrap with the associated kwk */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_configureAutoMode));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_configureAutoMode(keyWrapConfig));
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLSGI_DRV_CTRL_KEY_WRAP | mcuxClSgi_getKeyConf(kwk)));

  /* Get the pointer to DATIN0 (and DATIN1) to load the key material */
  uint8_t *pDATIN0A = (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_SFR_DATIN0_OFFSET);
  uint8_t *pDATIN0C = (pDATIN0A + 8);
  uint8_t *pDATIN1A = (uint8_t*)mcuxClSgi_Sfr_getAddr(MCUXCLSGI_SFR_DATIN1_OFFSET);
  uint8_t *pDATIN1C = (pDATIN1A + 8);

  /* Load the key material depending on the on the pSfrSeed value. For a plain key the pSfrSeed is
     NULL, and for a protected key the pSfrSeed is not NULL and contains the seed for SFR masking. */
  if (NULL == pSfrSeed)
  {
    /* Plain key - load as is */
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, pDATIN0A);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, pKeyMaterial);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, plainKeyMaterialSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pDATIN0A, pKeyMaterial, plainKeyMaterialSize));
  }
  else
  {
    /* Protected key - load using the special SFR Masking as produced by `mcuxClAes_keyUnwrapRfc3394_swDriven`. */

    /* Copy the SFRMask */
    uint32_t sfrMaskingSeed = *pSfrSeed;

    /* Load the (first) 128-bits of the key */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("parameters are 32 bit aligned")
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pDATIN0A);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pKeyMaterial);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked((uint32_t*)pDATIN0A, (const uint32_t*)pKeyMaterial, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE, sfrMaskingSeed));

    pKeyMaterial += MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pDATIN0C);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pKeyMaterial);
    MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked((uint32_t*)pDATIN0C, (const uint32_t*)pKeyMaterial, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE, sfrMaskingSeed));

    if (MCUXCLAES_AES256_KEY_SIZE == plainKeyMaterialSize)
    {
      /* If the key material size is 256bits, load the remaining 128-bits */
      pKeyMaterial += MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
      MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pDATIN1A);
      MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pKeyMaterial);
      MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked((uint32_t*)pDATIN1A, (const uint32_t*)pKeyMaterial, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE, sfrMaskingSeed));

      pKeyMaterial += MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
      MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pDATIN1C);
      MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pKeyMaterial);
      MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked((uint32_t*)pDATIN1C, (const uint32_t*)pKeyMaterial, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE, sfrMaskingSeed));
    }
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  }

  /* Wait for the SGI to finish the key wrap */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

  /* Read the result of the key wrap from the KEY_WRAP SFR.
   * The result size is the key material size + 8 bytes (MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE).
   * The SGI updates the SFR after each access until the full wrapped key is read. */

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Key data has to be aligned per CL use guidance.")
  uint32_t* pKeyDest = (uint32_t*) mcuxClKey_getKeyData(key);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
  /* TODO CLNS-16308: use new copy function here */
  pKeyDest[0] = mcuxClSgi_Sfr_readWrappedKeyWord();
  pKeyDest[1] = mcuxClSgi_Sfr_readWrappedKeyWord();
  pKeyDest[2] = mcuxClSgi_Sfr_readWrappedKeyWord();
  pKeyDest[3] = mcuxClSgi_Sfr_readWrappedKeyWord();
  pKeyDest[4] = mcuxClSgi_Sfr_readWrappedKeyWord();
  pKeyDest[5] = mcuxClSgi_Sfr_readWrappedKeyWord();

  if(MCUXCLAES_AES256_KEY_SIZE == plainKeyMaterialSize)
  {
    pKeyDest[6] = mcuxClSgi_Sfr_readWrappedKeyWord();
    pKeyDest[7] = mcuxClSgi_Sfr_readWrappedKeyWord();
    pKeyDest[8] = mcuxClSgi_Sfr_readWrappedKeyWord();
    pKeyDest[9] = mcuxClSgi_Sfr_readWrappedKeyWord();
  }

  /* Disable the AUTO mode */
  mcuxClSgi_Drv_resetAutoMode();

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_close));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_close(session));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_keyWrapRfc3394);
}
