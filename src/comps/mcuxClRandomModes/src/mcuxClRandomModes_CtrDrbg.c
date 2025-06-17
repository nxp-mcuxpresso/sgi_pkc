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

#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxClMemory.h>
#include <mcuxClAes.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClMemory_XORSecure_Internal.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <internal/mcuxClRandomModes_Private_NormalMode.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>
#include <internal/mcuxClRandomModes_Internal_SizeDefinitions.h>
#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClRandomModes_Private_ExitGates.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_castToContext_CtrDrbg_Generic)
static mcuxClRandomModes_Context_CtrDrbg_Generic_t* mcuxClRandomModes_castToContext_CtrDrbg_Generic(mcuxClRandom_Context_t context)
{
  MCUX_CSSL_ANALYSIS_START_CAST_TO_MORE_SPECIFIC_TYPE()
  return (mcuxClRandomModes_Context_CtrDrbg_Generic_t *) context;
  MCUX_CSSL_ANALYSIS_STOP_CAST_TO_MORE_SPECIFIC_TYPE()
}


/**
 * @brief This function implements the BCC function as specified in NIST SP800-90A.
 *        Assumes the key is already loaded by the calling function.
 *
 * @param  pSession             Handle for the current CL session
 * @param  mode[in]             Handle for the current Random Mode
 * @param  pData[in]            Pointer to input data
 * @param  dataLen[in]          Byte length of input data
 * @param  pOut[out]            Pointer to output buffer
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_bcc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_bcc(
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Mode_t mode,
        uint32_t * const pData,
        uint32_t dataLen,
        uint32_t *pOut)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_bcc);

    uint32_t keyLen = (uint32_t)(mode->securityStrength) / 8u;

    /* Initialize buffer in CPU workarea for the input block for the block cipher operations */
    uint32_t *pInputBlock = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLAES_BLOCK_SIZE_IN_WORDS);

    /* Initialize the chaining value in the output buffer with zeros */
    uint32_t *pChainingValue = pOut;
    MCUX_CSSL_DI_RECORD(setDI, (uint32_t)pChainingValue + MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int((uint8_t *)pChainingValue, 0u, MCUXCLAES_BLOCK_SIZE));

    /* Get number of input blocks to be processed */
    uint32_t numBlocks = dataLen / MCUXCLAES_BLOCK_SIZE;
    uint32_t blkSizeInWords = MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t);

    for (uint32_t i = 0u; i < numBlocks; i++)
    {
        /* Securely XOR chaining value to current input data block */
        /* pInputBlock = (pData + (i * blkSizeInWords)) ^ pChainingValue */
        MCUX_CSSL_DI_RECORD(xorParamsDst /* Not used */, (uint32_t) pInputBlock);
        MCUX_CSSL_DI_RECORD(xorParamsSrc /* Not used */, (uint32_t) (pData + (i * blkSizeInWords)));
        MCUX_CSSL_DI_RECORD(xorParamsSrc /* Not used */, (uint32_t) pChainingValue);
        MCUX_CSSL_DI_RECORD(xorParamsLength /* Not used */, (uint32_t) MCUXCLAES_BLOCK_SIZE);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XOR_secure_int));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XOR_secure_int(
                                       (uint8_t *) pInputBlock,
                                       (const uint8_t *) (pData + (i * blkSizeInWords)),
                                       (const uint8_t *) pChainingValue,
                                       (uint32_t) MCUXCLAES_BLOCK_SIZE));

        /* Load input Block for blockcipher operation */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput(pInputBlock));

        /* Encrypt the input block to obtain the new chaining value */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt(pSession, keyLen));

        MCUX_CSSL_DI_RECORD(sumOfBlockCipherCalls, 1u);
        MCUXCLBUFFER_INIT(chainingValueBuf, NULL, (uint8_t *)pChainingValue, MCUXCLAES_BLOCK_SIZE);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt(pSession, chainingValueBuf, NULL, keyLen));
    }

    /* Free CPU workarea used by this function (pInputBlock) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLAES_BLOCK_SIZE_IN_WORDS);

    MCUX_CSSL_DI_EXPUNGE(inputBlockLoads, MCUXCLAES_BLOCK_SIZE_IN_WORDS * numBlocks);
    MCUX_CSSL_DI_EXPUNGE(sumOfBlockCipherCalls, numBlocks);
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_bcc);
}



#define MCUXCLRANDOM_MAX_DF_BITS        512u

static uint32_t const mcuxClRandomModes_CtrDrbg_df_key[8u] = {
    0x03020100u, 0x07060504u, 0x0b0a0908u, 0x0f0e0d0cu,
    0x13121110u, 0x17161514u, 0x1b1a1918u, 0x1f1e1d1cu
};

/**
 * \brief This function implements the Block_Cipher_df function as specified in NIST SP800-90A.
 *
 * This function implements the derivation function Block_Cipher_df as specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession               Handle for the current CL session
 * \param  mode[in]               Handle for the current Random Mode
 * \param  pInputString[in/out]   Pointer to the input string and the output of the derivation function. The length is limited to (UINT32_MAX / 2).
 * \param  inputStringLen[in]     Byte length of the input string
 * \param  outputLen[in]          Byte length of the output
 *
 * \return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_df)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_df(
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Mode_t mode,
        uint8_t *pInputString,
        uint32_t inputStringLen,
        uint32_t outputLen)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_df);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inputStringLen, 0u, UINT32_MAX / 2u, MCUXCLRANDOM_STATUS_ERROR)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(outputLen, 1u, UINT32_MAX, MCUXCLRANDOM_STATUS_ERROR)

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    uint32_t seedLen = pDrbgMode->pDrbgVariant->seedLen;
    uint32_t keyLen = (uint32_t)(mode->securityStrength) / 8u;

    /*
     * Step 1 specified in NIST SP800-90A:
     *
     * Verify that seedLen is valid. Invalid values should not occur and will trigger a FAULT_ATTACK.
     */
    if (MCUXCLRANDOM_MAX_DF_BITS < seedLen * 8u)
    {
        MCUXCLSESSION_FAULT(pSession, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /*
     * Steps 2-7 specified in NIST SP800-90A:
     *
     * Prepare values S and IV (input for BCC function) in CPU workarea:
     * layout: IV || L || N || input_string || 0x80 || 0 padding
     * length: 16    4    4    seed size       1       (16-(4+4+seedSize+1)%16)%16
     */

    /* Allocate space for IV */
    uint32_t *pIV = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLAES_BLOCK_SIZE_IN_WORDS);
    /* CLNS-17418 handle error */

    /* Determine the byte length of S: (4+4+seedSize+1 + ((16-(4+4+seedSize+1)%16)%16)) */
    uint32_t lenOfS = sizeof(uint32_t)+sizeof(uint32_t)+inputStringLen;
    uint32_t tempLen = lenOfS;
    /* add 1 for 0x80 */
    lenOfS += 1u;
    /* pad with zeros if to align with the block size */
    if (0u != (lenOfS % MCUXCLAES_BLOCK_SIZE))
    {
        lenOfS += (MCUXCLAES_BLOCK_SIZE - (lenOfS % MCUXCLAES_BLOCK_SIZE));
    }

    /* Allocate space for S */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pS is always valid in work area.")
    uint32_t *pS = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(lenOfS));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    /* CLNS-17418 handle error */

    /* Pre-initialize the IV value with zeros to take care of the padding with zeros */
    MCUX_CSSL_DI_RECORD(setDI, (uint32_t)pIV + MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int((uint8_t*)pIV, 0u, MCUXCLAES_BLOCK_SIZE));
    MCUX_CSSL_DI_RECORD(sumOfMemSetCalls, 1u);

    /* Pre-initialize S with zeros to take care of cases where padding with 0 is needed at the end */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pSByte will be in the valid range pS[0 ~ lenOfS].");
    uint8_t *pSByte = (uint8_t *) pS;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_DI_RECORD(setDI, (uint32_t)pSByte + lenOfS);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int(pSByte, 0u, lenOfS));
    MCUX_CSSL_DI_RECORD(sumOfMemSetCalls, 1u);

    /* Calculate (big integer) values L and N and initialize value S as specified in NIST SP800-90A */
    uint32_t L = inputStringLen << 24;
    uint32_t S = outputLen << 24;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pS is always valid in work area.")
    pS[0] = L;
    pS[1] = S;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pSByte+tempLen will be in the valid range pS[0 ~ lenOfS].");
    pSByte[tempLen] = 0x80;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    /* Record input data for mcuxClMemory_copy_secure_int() */
    MCUX_CSSL_DI_RECORD(copySecureDI, (uint32_t) (&pS[2]) + (uint32_t)pInputString + inputStringLen);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int((uint8_t *) &pS[2], (uint8_t const *)pInputString, inputStringLen));
    MCUX_CSSL_DI_RECORD(sumOfMemCopyCalls, 1u);


    /*
     * Steps 8-11 specified in NIST SP800-90A:
     *
     * Call BCC function in a loop to determine intermediate values K and X.
     */

    /* Allocate space for a temp buffer (temp1) in CPU workarea for the output of the BCC loop.
     * This buffer will later contain the values K and X concatenated:
     * layout:   K      || X  || unused
     * length:   keylen    16    (keylen % 16)
     *
     * NOTE: Additional space is reserved behind K and X for the case keyLen is not a multiple of the block size
     */
    uint32_t temp1Len = MCUXCLRANDOMMODES_ALIGN_TO_AES_BLOCKSIZE(keyLen) + MCUXCLAES_BLOCK_SIZE;
    uint32_t *pTemp1 = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(temp1Len));
    /* CLNS-17418 handle error */

    /* Load Key for BCC function */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey(mcuxClRandomModes_CtrDrbg_df_key, keyLen));
    /* Call BCC function in a loop */
    uint32_t outBlocks = temp1Len / MCUXCLAES_BLOCK_SIZE;
    uint32_t i;
    for (i = 0; i < outBlocks; i++)
    {
        /* Update IV value with the next loop counter converted to a (big endian) 32 bit integer padded with zeros */
        pIV[0] = i << 24;

        /* Call BCC function */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_bcc));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_bcc(
                                          pSession,
                                          mode,
                                          pIV,
                                          MCUXCLAES_BLOCK_SIZE + lenOfS,
                                          &pTemp1[i*MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t)]));
        MCUX_CSSL_DI_RECORD(sumOfBccCalls, 1u);
    }

    /* Initialize pointers to K and X */
    uint32_t *pK = pTemp1;
    uint32_t *pX = &pTemp1[keyLen/sizeof(uint32_t)];


    /*
     * Steps 12-15 specified in NIST SP800-90A:
     *
     * Compute and return the output of the derivation function.
     */

    /* Reuse CPU workarea buffer IV || S for value temp2, the result of the upcoming block encryption loop */
    uint32_t *pTemp2 = pIV;

    /* Load input Block for blockcipher operation */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput(pX));

    /* Load Key for blockcipher operation */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey(pK, keyLen));

    /* Execute first block encryption and store the result directly in temp2 */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt(pSession, keyLen));

    MCUX_CSSL_DI_RECORD(sumOfBlockCipherCalls, 1u);
    MCUXCLBUFFER_INIT(temp2Buf, NULL, (uint8_t *)pTemp2, MCUXCLAES_BLOCK_SIZE);

    /* Execute the remaining block encryption operations.
     *
     * NOTE: Different to the specification in NIST SP800-90A, input and output of the block encryption
     *       are stored directly in the temp2 buffer. */
    uint32_t j;
    outBlocks = (uint32_t) (((outputLen - 1U) / MCUXCLAES_BLOCK_SIZE) + 1u);
    MCUXCLBUFFER_INIT(temp2LoopBuf, NULL, (uint8_t *)pTemp2, MCUXCLAES_BLOCK_SIZE + lenOfS);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt(pSession, temp2Buf, NULL, keyLen));

    for (j = 1u; j < outBlocks; j++)
    {
        /* Load input Block for blockcipher operation */
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput(&pTemp2[((j-1u)*MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t))]));

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt(pSession, keyLen));

        MCUX_CSSL_DI_RECORD(sumOfBlockCipherCalls, 1u);
        MCUXCLBUFFER_UPDATE(temp2LoopBuf, MCUXCLAES_BLOCK_SIZE);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt(pSession, temp2LoopBuf, NULL, keyLen));
    }

    /* Copy the result to the output buffer */
    /* Record input data for mcuxClMemory_copy_secure_int() */
    MCUX_CSSL_DI_RECORD(copySecureDI, (uint32_t)pIV + (uint32_t)pInputString + outputLen);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(pInputString, (uint8_t const *)pIV, outputLen));
    MCUX_CSSL_DI_RECORD(sumOfMemCopyCalls, 1u);

    /* Free CPU workarea allocated by this function (pTemp1 + pS + pIV) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLAES_BLOCK_SIZE_IN_WORDS + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(temp1Len + lenOfS));

    MCUX_CSSL_DI_EXPUNGE(inputBlockLoads, MCUXCLAES_BLOCK_SIZE_IN_WORDS);
    MCUX_CSSL_DI_EXPUNGE(inputBlockLoads, MCUXCLAES_BLOCK_SIZE_IN_WORDS * (outBlocks - 1u));
    MCUX_CSSL_DI_EXPUNGE(sumOfMemCopyCalls, 2u);
    MCUX_CSSL_DI_EXPUNGE(sumOfMemSetCalls, 2u);
    MCUX_CSSL_DI_EXPUNGE(sumOfBccCalls, temp1Len / MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_DI_EXPUNGE(sumOfBlockCipherCalls, (uint32_t) (outBlocks));

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_df);
}



MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClRandomModes_DrbgVariantDescriptor_t mcuxClRandomModes_DrbgVariantDescriptor_CtrDrbg_AES256 =
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    .reseedInterval = MCUXCLRANDOMMODES_RESEED_INTERVAL_CTR_DRBG_AES256,
    .seedLen = MCUXCLRANDOMMODES_SEEDLEN_CTR_DRBG_AES256,
    .initSeedSize = MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256,
    .reseedSeedSize = MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES256
};

/**
 * \brief This function instantiates a CTR_DRBG following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A
 *
 * This function instantiates a CTR_DRBG in following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A.
 * The function obtains entropy input and nonce for the DRBG seed from the TRNG.
 *
 * \param  pSession                     Handle for the current CL session
 * \param  mode[in]                     Handle for the current Random Mode
 * \param  context[in]                  Handle for the current Random Context
 * \param  pEntropyInputAndNonce[in]    Pointer to entropy input and nonce
 *
 * \return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm, mcuxClRandomModes_instantiateAlgorithm_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_instantiateAlgorithm(
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Mode_t mode,
        mcuxClRandom_Context_t context,
        uint8_t *pEntropyInputAndNonce
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm);

    mcuxClRandomModes_Context_CtrDrbg_Generic_t *pRngCtxGeneric = mcuxClRandomModes_castToContext_CtrDrbg_Generic(context);

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    uint32_t seedLen = pDrbgMode->pDrbgVariant->seedLen;
    uint32_t initSeedSize = pDrbgMode->pDrbgVariant->initSeedSize;

    /* This max is needed as initSeedSize might be smaller than seedlen, but the df uses this buffer both for input and output. */
    uint32_t dfBufferSize = MCUXCLCORE_MAX(initSeedSize, seedLen);
    uint32_t *pSeedMaterial = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(dfBufferSize));
    /* CLNS-17418 handle error */

    /* Securely copy the seed to the seedMaterial buffer */
    MCUX_CSSL_DI_RECORD(copySecureDI, (uint32_t)pSeedMaterial + (uint32_t)pEntropyInputAndNonce + initSeedSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int((uint8_t *)pSeedMaterial, (uint8_t const *)pEntropyInputAndNonce, initSeedSize));

    /* pSeedMaterial use as both input and output */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_df));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_df(
                    pSession,
                    mode,
                    (uint8_t *)pSeedMaterial,
                    initSeedSize,
                    seedLen));

    /* Set to 0 counter V and key K in context
     * According to sp800-90A, V and Key need to be initialized with zeros.
     *
     * NOTE: V and K lie next to each other in the context */
    uint32_t *pState = pRngCtxGeneric->state;
    MCUX_CSSL_DI_RECORD(setDI, (uint32_t)pState + seedLen);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int((uint8_t *)pState, 0u, seedLen));
    MCUX_CSSL_DI_RECORD(sumOfMemSetCalls, 1u);

    /* Load counter V for blockcipher operation */
    uint32_t securityStrength = (uint32_t)(mode->securityStrength);
    uint32_t *pV = &pState[securityStrength/MCUXCLRANDOMMODES_BITSIZE_OF_WORD];
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput(pV));

    /* Update the CTR_DRBG state
     *
     * NOTE: The size of the provided DRBG seed equals seedLen, so no padding with zeros is needed to derive the seedMaterial from the entryopInput
     */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_UpdateState));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_UpdateState(
                    pSession,
                    mode,
                    context,
                    pSeedMaterial));

    /* Free workarea (pSeedMaterial) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(dfBufferSize));

    /* Initialize the reseed counter */
    pRngCtxGeneric->reseedCounter = 1u;

    MCUX_CSSL_DI_EXPUNGE(sumOfMemSetCalls, 1u);
    MCUX_CSSL_DI_EXPUNGE(inputBlockLoads, MCUXCLAES_BLOCK_SIZE_IN_WORDS);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm);
}


/**
 * \brief This function reseeds a CTR_DRBG following the lines of the function CTR_DRBG_Reseed_algorithm as specified in NIST SP800-90A
 *
 * This function reseeds a CTR_DRBG following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession[in]         Handle for the current CL session
 * \param  mode[in]             Handle for the current Random Mode
 * \param  context[in]          Handle for the current Random Context
 * \param  pEntropyInput[in]    Pointer to entropy input
 *
 * \return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_reseedAlgorithm, mcuxClRandomModes_reseedAlgorithm_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_reseedAlgorithm(
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Mode_t mode,
        mcuxClRandom_Context_t context,
        uint8_t *pEntropyInput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_reseedAlgorithm);

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    uint32_t seedLen = pDrbgMode->pDrbgVariant->seedLen;
    uint32_t reseedSeedSize = pDrbgMode->pDrbgVariant->reseedSeedSize;

    /* This max is needed as reseedSeedSize might be smaller than seedlen, but the df uses this buffer both for input and output. */
    uint32_t dfBufferSize = MCUXCLCORE_MAX(reseedSeedSize, seedLen);
    uint32_t *pSeedMaterial = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(dfBufferSize));
    /* CLNS-17418 handle error */

    /* Securely copy the seed to the seedMaterial buffer */
    MCUX_CSSL_DI_RECORD(copySecureDI, (uint32_t)pSeedMaterial + (uint32_t)pEntropyInput + reseedSeedSize);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int((uint8_t *)pSeedMaterial, (uint8_t const *)pEntropyInput, reseedSeedSize));

    /* pSeedMaterial use as both input and output */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_df));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_df(
                pSession,
                mode,
                (uint8_t *)pSeedMaterial,
                reseedSeedSize,
                seedLen));

    /* Load counter V for blockcipher operation */
    mcuxClRandomModes_Context_CtrDrbg_Generic_t *pRngCtxGeneric = mcuxClRandomModes_castToContext_CtrDrbg_Generic(context);
    uint32_t *pState = pRngCtxGeneric->state;
    uint32_t securityStrength = (uint32_t)(mode->securityStrength);
    uint32_t *pV = &pState[securityStrength/MCUXCLRANDOMMODES_BITSIZE_OF_WORD];
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput(pV));

    /* Update the CTR_DRBG state */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_UpdateState));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_UpdateState(
                pSession,
                mode,
                context,
                pSeedMaterial));

    /* Reset the reseed counter */
    pRngCtxGeneric->reseedCounter = 1u;

    /* Free workarea (pSeedMaterial) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(dfBufferSize));
    MCUX_CSSL_DI_EXPUNGE(inputBlockLoads, MCUXCLAES_BLOCK_SIZE_IN_WORDS);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_reseedAlgorithm);
}


/**
 * \brief This function generates random numbers from a CTR_DRBG following the lines of the function CTR_DRBG_Generate_algorithm as specified in NIST SP800-90A
 *
 * \param  pSession             Handle for the current CL session
 * \param  mode[in]             Handle for the current Random Mode
 * \param  context[in]          Handle for the current Random Context
 * \param  pOut[out]            Output buffer to which the generated randomness will be written
 * \param  outLength[in]        Number of requested random bytes
 * \param  pXorMask[in]         Boolean masking used for masking DRBG output
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK         if the random number generation finished successfully
 *   - MCUXCLRANDOM_STATUS_ERROR           if a memory allocation error occured
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the random number generation failed due to other unexpected reasons
 */
// TODO: Not clear why suppression is needed here. Moreover there is a MSG2 violation <Parse recovery warning (RW.ROUTINE_NOT_EMITTED)> for this
// function (CID 36583677). Should be clarified.
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_generateAlgorithm, mcuxClRandomModes_generateAlgorithm_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_generateAlgorithm(
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Mode_t mode,
        mcuxClRandom_Context_t context,
        mcuxCl_Buffer_t pOut,
        uint32_t outLength,
        const uint32_t *pXorMask)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_generateAlgorithm);

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    uint32_t seedLen = pDrbgMode->pDrbgVariant->seedLen;

    /* Load counter V for blockcipher operation */
    mcuxClRandomModes_Context_CtrDrbg_Generic_t *pRngCtxGeneric = mcuxClRandomModes_castToContext_CtrDrbg_Generic(context);
    uint32_t *pState = pRngCtxGeneric->state;

    /* The number of reseed attempts is limited to 2^48 according to NIST SP800-90A */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pRngCtxGeneric->reseedCounter, 0u, (1uLL << 48u), MCUXCLRANDOM_STATUS_ERROR)

    uint32_t securityStrength = (uint32_t)(mode->securityStrength);
    uint32_t *pV = &pState[securityStrength/MCUXCLRANDOMMODES_BITSIZE_OF_WORD];
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadInput(pV));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_generateOutput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_generateOutput(
                    pSession,
                    mode,
                    context,
                    pOut,
                    outLength,
                    pXorMask));

    /* Init additionalInput for state update in CPU workarea to all zeros and update the CTR_DRBG state */
    uint32_t *pAdditionalInput = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(seedLen));
    /* handle error CLNS-17418 */

    MCUX_CSSL_DI_RECORD(setDI, (uint32_t)pAdditionalInput + seedLen);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set_int((uint8_t *)pAdditionalInput, 0u, seedLen));

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_UpdateState));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_UpdateState(
                    pSession,
                    mode,
                    context,
                    pAdditionalInput));

    /* Increment the reseed counter */
    pRngCtxGeneric->reseedCounter += 1u;

    /* Free workarea (pAdditionalInput) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(seedLen));
    MCUX_CSSL_DI_EXPUNGE(inputBlockLoads, MCUXCLAES_BLOCK_SIZE_IN_WORDS);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_generateAlgorithm);
}


/**
 * @brief This function updates the internal state of a CTR_DRBG as specified in NIST SP800-90A
 *
 * @param  pSession             Handle for the current CL session
 * @param  mode[in]             Handle for the current Random Mode
 * @param  context[in/out]      Handle for the current Random Context
 * @param  pProvidedData[in]    Additional data to incorporate into the state
 *
 * @return void
 *
 * @note This function saves the whole state(key and v) to the context.
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_UpdateState)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_UpdateState(
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Mode_t mode,
        mcuxClRandom_Context_t context,
        uint32_t *pProvidedData
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_UpdateState);

    mcuxClRandomModes_Context_CtrDrbg_Generic_t *pCtx = mcuxClRandomModes_castToContext_CtrDrbg_Generic(context);
    uint32_t *pState = pCtx->state;

    const mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = mcuxClRandomModes_castToDrbgModeDescriptor(mode->pDrbgMode);

    uint32_t seedLen = pDrbgMode->pDrbgVariant->seedLen;
    uint32_t securityStrength = (uint32_t)(mode->securityStrength);
    uint32_t *pKey = pState;

    /* Load Key for blockcipher operation */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey(pKey, securityStrength/8u));

    /* produce the new Key and V */
    uint32_t *pTemp = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLRANDOMMODES_ALIGN_TO_AES_BLOCKSIZE(seedLen) / sizeof(uint32_t));
    /* Handle error CLNS-17418 */

    /* V=(V+1) mod 2^Blocklen */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_incV(pSession));

    uint32_t seedLenInBlkSize = MCUXCLRANDOMMODES_ALIGN_TO_AES_BLOCKSIZE(seedLen) / MCUXCLAES_BLOCK_SIZE;

    MCUXCLBUFFER_INIT(tempBuf, NULL, (uint8_t *) pTemp, (MCUXCLRANDOMMODES_ALIGN_TO_AES_BLOCKSIZE(seedLen)));

    for (uint32_t i = 0u; i < seedLenInBlkSize; i++)
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt(pSession, securityStrength/8u));

        if((i+1u) < seedLenInBlkSize)
        {
            /* V=(V+1) mod 2^Blocklen */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_incV(pSession));
        }

        MCUX_CSSL_DI_RECORD(sumOfBlockCipherCalls, 1u);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt(pSession, tempBuf, NULL, securityStrength/8u));
        /* move tempBuf as mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt writes consecutive in tempBuf */
        MCUXCLBUFFER_UPDATE(tempBuf, MCUXCLAES_BLOCK_SIZE);
    }

    /* Use Secure XOR for pTemp = pTemp ^ pProvidedData */
    MCUX_CSSL_DI_RECORD(xorParamsDst /* Not used */, (uint32_t) pTemp);
    MCUX_CSSL_DI_RECORD(xorParamsSrc /* Not used */, (uint32_t) pTemp);
    MCUX_CSSL_DI_RECORD(xorParamsSrc /* Not used */, (uint32_t) pProvidedData);
    MCUX_CSSL_DI_RECORD(xorParamsLength /* Not used */, seedLen);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_XOR_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_XOR_secure_int(
                                    (uint8_t *) pTemp,
                                    (const uint8_t *) pTemp,
                                    (const uint8_t *) pProvidedData,
                                    seedLen));

    /* update the key V in context */
    MCUX_CSSL_DI_RECORD(copySecureDI, (uint32_t)pKey + (uint32_t)pTemp + securityStrength/8u + MCUXCLAES_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int((uint8_t *)pKey, (uint8_t const *)pTemp, securityStrength/8u + MCUXCLAES_BLOCK_SIZE));

    /* Free workarea (pTemp) */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ALIGN_TO_AES_BLOCKSIZE(seedLen) / sizeof(uint32_t));

    /* Balance DI */
    MCUX_CSSL_DI_EXPUNGE(sumOfBlockCipherCalls, seedLenInBlkSize);
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_UpdateState);
}

/**
 * \brief This function generates full blocks output from the internal state of a CTR_DRBG as specified in NIST SP800-90A
 *
 * \param  pSession             Handle for the current CL session
 * \param  keyLength[in]        Length of the key
 * \param  pOut[out]            Output buffer to which the generated randomness will be written
 * \param  outLength[in]        Number of requested random bytes
 * \param  ppXorMask[in]        Boolean masking used for masking DRBG output
 *
 * \return void
 *
 * Data Integrity: Record((outLength - outLength % MCUXCLAES_BLOCK_SIZE)/MCUXCLAES_BLOCK_SIZE)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_generateFullBlocksOutput)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_generateFullBlocksOutput(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
        mcuxClSession_Handle_t pSession,
        uint32_t keyLength,
        mcuxCl_Buffer_t pOut,
        uint32_t outLength,
        const uint32_t **ppXorMask
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_generateFullBlocksOutput);

    const uint32_t requestSizeRemainingBytes = outLength % MCUXCLAES_BLOCK_SIZE;

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(requestSizeRemainingBytes, 0u, outLength, MCUXCLRANDOM_STATUS_ERROR)
    uint32_t requestSizeFullBlocksBytes = outLength - requestSizeRemainingBytes;

    MCUXCLBUFFER_DERIVE_RW(pOutCur, pOut, 0u);

    /* Request as many random bytes as possible with full word size. */
    while (requestSizeFullBlocksBytes > 0u)
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt(pSession, keyLength));

        requestSizeFullBlocksBytes -= MCUXCLAES_BLOCK_SIZE;
        if((requestSizeFullBlocksBytes > 0u) || (requestSizeRemainingBytes > 0u))
        {
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_incV(pSession));
        }

        MCUX_CSSL_DI_RECORD(sumOfRequestedFullBlockIterations, 1u);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt(pSession, pOutCur, *ppXorMask, keyLength));

        MCUXCLBUFFER_UPDATE(pOutCur, MCUXCLAES_BLOCK_SIZE);
        if(*ppXorMask != NULL) {
            *ppXorMask += MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t);
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_generateFullBlocksOutput);
}

/**
 * \brief This function generates remaining bytes output from the internal state of a CTR_DRBG as specified in NIST SP800-90A
 *
 * \param  pSession             Handle for the current CL session
 * \param  keyLength[in]        Length of the key
 * \param  pOut[out]            Output buffer to which the generated randomness will be written
 * \param  outLength[in]        Number of requested random bytes
 * \param  pXorMask[in]         Boolean masking used for masking DRBG output
 *
 * \return void
 *
 * Data Integrity: Expunge((outLength - outLength % MCUXCLAES_BLOCK_SIZE)/MCUXCLAES_BLOCK_SIZE)
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_generateRemainingBytesOutput)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_generateRemainingBytesOutput(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
        mcuxClSession_Handle_t pSession,
        uint32_t keyLength,
        mcuxCl_Buffer_t pOut,
        uint32_t outLength,
        const uint32_t *pXorMask
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_generateRemainingBytesOutput);

    const uint32_t requestSizeRemainingBytes = outLength % MCUXCLAES_BLOCK_SIZE;

    /* If requested size is not a multiple of block size, request one (additional) block and use it only partially. */
    if (requestSizeRemainingBytes > 0u)
    {
        uint8_t pRequestRemaining[MCUXCLAES_BLOCK_SIZE] = {0u};

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_StartBlockEncrypt(pSession, keyLength));

        MCUX_CSSL_DI_EXPUNGE(sumOfRequestedFullBlockIterations, (outLength - requestSizeRemainingBytes)/MCUXCLAES_BLOCK_SIZE);

        uint32_t pXorMaskCopy[MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t)] = {0u};
        /* Copy the mask. */
        if(pXorMask != NULL)
        {
            MCUX_CSSL_DI_RECORD(copySecureDI, pXorMaskCopy);
            MCUX_CSSL_DI_RECORD(copySecureDI, pXorMask);
            MCUX_CSSL_DI_RECORD(copySecureDI, requestSizeRemainingBytes);
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int((uint8_t*) pXorMaskCopy, (const uint8_t*)pXorMask, requestSizeRemainingBytes));
        }
        MCUXCLBUFFER_INIT(requestRemainingBuf, NULL, pRequestRemaining, MCUXCLAES_BLOCK_SIZE);
        /* Copy the remaining bytes from the buffer to output. */
        MCUX_CSSL_DI_RECORD(buffParams, (uint32_t)pOut + (uint32_t)pRequestRemaining + requestSizeRemainingBytes);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_CompleteBlockEncrypt(pSession, requestRemainingBuf, pXorMask != NULL ? pXorMaskCopy : NULL, keyLength));

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write_secure));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write_secure(pOut, 0u, pRequestRemaining, requestSizeRemainingBytes));
    }
    else
    {
        MCUX_CSSL_DI_EXPUNGE(sumOfRequestedFullBlockIterations, outLength/MCUXCLAES_BLOCK_SIZE);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_generateRemainingBytesOutput);
}

/**
 * \brief This function generates output from the internal state of a CTR_DRBG as specified in NIST SP800-90A
 *
 * \param  pSession             Handle for the current CL session
 * \param  mode[in]             Handle for the current Random Mode
 * \param  context[in]          Handle for the current Random Context
 * \param  pOut[out]            Output buffer to which the generated randomness will be written
 * \param  outLength[in]        Number of requested random bytes
 * \param  pXorMask[in]         Boolean masking used for masking DRBG output
 *
 * \return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_generateOutput)
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClRandomModes_CtrDrbg_generateOutput(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Mode_t mode,
        mcuxClRandom_Context_t context,
        mcuxCl_Buffer_t pOut,
        uint32_t outLength,
        const uint32_t *pXorMask
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_generateOutput);

    mcuxClRandomModes_Context_CtrDrbg_Generic_t *pCtx = mcuxClRandomModes_castToContext_CtrDrbg_Generic(context);

    uint32_t *pKey = pCtx->state;
    const uint32_t securityStrength = (uint32_t)(mode->securityStrength);
    const uint32_t keyLength = securityStrength / 8u;

    /* Load Key for blockcipher operation */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_AES_BlockEncrypt_LoadKey(pKey, keyLength));
    if(outLength > 0u)
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRandomModes_CtrDrbg_incV(pSession));
    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_generateFullBlocksOutput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        mcuxClRandomModes_CtrDrbg_generateFullBlocksOutput(pSession, keyLength, pOut, outLength, &pXorMask)
    );

    const uint32_t requestSizeRemainingBytes = outLength % MCUXCLAES_BLOCK_SIZE;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("outLength cannot be smaller than remaining requestSizeRemainingBytes")
    const uint32_t requestSizeFullBlocksBytes = outLength - requestSizeRemainingBytes;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    MCUXCLBUFFER_DERIVE_RW(pOutCur, pOut, requestSizeFullBlocksBytes);

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_generateRemainingBytesOutput));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        mcuxClRandomModes_CtrDrbg_generateRemainingBytesOutput(pSession, keyLength, pOutCur, outLength, pXorMask)
    );

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClRandomModes_CtrDrbg_generateOutput);
}
