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

#include <mcuxClRandom.h>
#include <mcuxClAes.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <internal/mcuxClRandomModes_Private_ExitGates.h>
#include <internal/mcuxClResource_Internal_Types.h>

/* ctr drbg defines */
#define MCUXCLRANDOMMODES_CTR_DRBG_SGI_MODE_GENERAL (MCUXCLSGI_DRV_CTRL_DATOUT_RES_END_UP | \
                                              MCUXCLSGI_DRV_CTRL_INKEYSEL(0u)            | \
                                              MCUXCLSGI_DRV_CTRL_INSEL_DATIN0            | \
                                              MCUXCLSGI_DRV_CTRL_ENC                     | \
                                              MCUXCLSGI_DRV_CTRL_AES_EN)

#define MCUXCLRANDOMMODES_CTR_DRBG_MODE_AES128_ENCRYPT (MCUXCLRANDOMMODES_CTR_DRBG_SGI_MODE_GENERAL |      \
                                                    MCUXCLSGI_DRV_CTRL_OUTSEL_RES                  |      \
                                                    MCUXCLSGI_DRV_CTRL_AES128)

#define MCUXCLRANDOMMODES_CTR_DRBG_MODE_AES192_ENCRYPT (MCUXCLRANDOMMODES_CTR_DRBG_SGI_MODE_GENERAL |      \
                                                    MCUXCLSGI_DRV_CTRL_OUTSEL_RES                  |      \
                                                    MCUXCLSGI_DRV_CTRL_AES192)

#define MCUXCLRANDOMMODES_CTR_DRBG_MODE_AES256_ENCRYPT (MCUXCLRANDOMMODES_CTR_DRBG_SGI_MODE_GENERAL |      \
                                                    MCUXCLSGI_DRV_CTRL_OUTSEL_RES                  |      \
                                                    MCUXCLSGI_DRV_CTRL_AES256)

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_requestHW)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_requestHW(mcuxClSession_Handle_t pSession)
{
 MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_requestHW);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Request));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Request(pSession, MCUXCLRESOURCE_HWSTATUS_INTERRUPTABLE));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_requestHW);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_releaseHW)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_releaseHW(mcuxClSession_Handle_t pSession)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_releaseHW);


    /* Uninitialize (and release) the SGI hardware */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_Uninit));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_Uninit(pSession));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_releaseHW);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_cleanUpHW)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_cleanUpHW(void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_cleanUpHW);

    // TODO CLNS-16291: FLUSH_KEY for SGI is not usable anymore with preloaded keys
    // mcuxClSgi_Drv_enableFlush(MCUXCLSGI_DRV_FLUSH_ALL);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_cleanUpHW);
}

/* Data Integrity: RECORD(MCUXCLAES_BLOCK_SIZE_IN_WORDS) */
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput(
    uint32_t *pInputBlock
)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput);
    /* Load input Block into SGI_DATIN0 */
    for(uint32_t i = 0u; i < (MCUXCLAES_BLOCK_SIZE_IN_WORDS); i++)
    {
        mcuxClSgi_Drv_loadWord(MCUXCLSGI_DRV_DATIN0_OFFSET + (4u*i), pInputBlock[i]);
        MCUX_CSSL_DI_RECORD(inputBlockLoads, 1u);
    }
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey(
    uint32_t const *pKey,
    uint32_t keyLength
)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey);
    /* Load key into the SGI_KEY0 */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_loadKey_secure));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClSgi_Utils_loadKey_secure(MCUXCLSGI_DRV_KEY0_OFFSET, (const uint8_t*)pKey, keyLength)
    );
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey);
}

/* This function expects the block to start to encrypt in SGI DAT0 register. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt(
    mcuxClSession_Handle_t pSession,
    uint32_t keyLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt);

    //MCUX_CSSL_FP_SWITCH_DECL(switchProtector);
    MCUX_CSSL_ANALYSIS_START_PATTERN_SWITCH_STATEMENT_RETURN_TERMINATION()
    switch(keyLength)
    {
        case MCUXCLAES_AES128_KEY_SIZE:
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLRANDOMMODES_CTR_DRBG_MODE_AES128_ENCRYPT));
            //MCUX_CSSL_FP_SWITCH_CASE(switchProtector, MCUXCLAES_AES128_KEY_SIZE);
            MCUX_CSSL_DI_RECORD(switchKeySize, MCUXCLAES_AES128_KEY_SIZE);
        break;
        case MCUXCLAES_AES192_KEY_SIZE:
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLRANDOMMODES_CTR_DRBG_MODE_AES192_ENCRYPT));
            //MCUX_CSSL_FP_SWITCH_CASE(switchProtector, MCUXCLAES_AES192_KEY_SIZE);
            MCUX_CSSL_DI_RECORD(switchKeySize, MCUXCLAES_AES192_KEY_SIZE);
        break;
        case MCUXCLAES_AES256_KEY_SIZE:
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(MCUXCLRANDOMMODES_CTR_DRBG_MODE_AES256_ENCRYPT));
            //MCUX_CSSL_FP_SWITCH_CASE(switchProtector, MCUXCLAES_AES256_KEY_SIZE);
            MCUX_CSSL_DI_RECORD(switchKeySize, MCUXCLAES_AES256_KEY_SIZE);
        break;
        default:
            MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_SWITCH_STATEMENT_RETURN_TERMINATION()

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt);
}


/* This function get encrypt result. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt(
    mcuxClSession_Handle_t pSession,
    mcuxCl_Buffer_t  pOut,
    const uint32_t *pXorMask,
    uint32_t keyLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

    if(pXorMask != NULL)
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI(MCUXCLSGI_DRV_DATOUT_OFFSET, pOut, 0u, pXorMask));

        /* copy out result */
        /* Write to buffer from SGI, src pointer is calculated from sgiSfrDatIndex */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_storeMasked128BitBlock_buffer));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_storeMasked128BitBlock_buffer(pSession,
                                                                               MCUXCLSGI_DRV_DATOUT_OFFSET,
                                                                               pOut,
                                                                               0u,
                                                                               pXorMask));
    }
    else
    {
        /* copy out result */
        MCUX_CSSL_DI_RECORD(bufferReadDI, (uint32_t)pOut + 0u + (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET) + MCUXCLAES_BLOCK_SIZE);
        /* Write to buffer from SGI, src pointer is calculated from sgiSfrDatIndex */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock_buffer));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock_buffer(pSession, MCUXCLSGI_DRV_DATOUT_OFFSET, pOut, 0u));
    }

    MCUX_CSSL_DI_EXPUNGE(switchKeySize, keyLength);
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_incV)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_incV(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_incV);

    /* Record for mcuxClSgi_Drv_incrementData call */
    MCUX_CSSL_DI_RECORD(incLength, MCUXCLAES_BLOCK_SIZE);

    uint32_t vBeforeIncrement[MCUXCLAES_BLOCK_SIZE_IN_WORDS] = {0};
    MCUXCLBUFFER_INIT(vBeforeIncrementBuf, NULL, (uint8_t *)&vBeforeIncrement[0], MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_DI_RECORD(bufferWriteDI, (uint32_t)vBeforeIncrementBuf + 0u + (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET) + MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock_buffer));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock_buffer(pSession, MCUXCLSGI_DRV_DATIN0_OFFSET,
                                                                     vBeforeIncrementBuf,
                                                                     0u));

    /* Increment SGI DATIN0 register */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_incrementData));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_incrementData(MCUXCLSGI_DRV_DATIN0_OFFSET, MCUXCLAES_BLOCK_SIZE));

    uint32_t vAfterIncrement[MCUXCLAES_BLOCK_SIZE_IN_WORDS] = {0};
    MCUXCLBUFFER_INIT(vAfterIncrementBuf, NULL, (uint8_t *)&vAfterIncrement[0], MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_DI_RECORD(bufferWriteDI, (uint32_t)vAfterIncrementBuf + 0u + (uint32_t)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATIN0_OFFSET) + MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock_buffer));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock_buffer(pSession, MCUXCLSGI_DRV_DATIN0_OFFSET,
                                                                     vAfterIncrementBuf,
                                                                     0u));

    /* Check whether at the least the least significant word was updated or not */
    if(vBeforeIncrement[MCUXCLAES_BLOCK_SIZE_IN_WORDS-1u] == vAfterIncrement[MCUXCLAES_BLOCK_SIZE_IN_WORDS-1u])
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_incV);
}
