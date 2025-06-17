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

/** @file  mcuxClAes_KeyEncodingMechanisms.c
 *  @brief Implementations of internal functions that take care of AES key
 *         encodings using the SGI.
 */

#include <mcuxClMemory.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSgi_Utils.h>
#include <mcuxClAes.h>
#include <mcuxClKey.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClAes_KeyEncodingMechanisms_Sgi.h>
#include <internal/mcuxClAes_Internal_Constants.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClMemory_Compare_Internal.h>
#include <internal/mcuxClMemory_CopyWords_Internal.h>
#include <internal/mcuxClMemory_Clear_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClPrng_Internal.h>





MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_keyLoad_rfc3394, mcuxClKey_LoadFuncPtr_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_keyLoad_rfc3394(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  uint8_t **ppDest,
  mcuxClKey_KeyChecksum_t * pKeyChecksums,
  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_keyLoad_rfc3394);

  /* If spec specifies to set the key pointer to ppDest */
  if((MCUXCLKEY_ENCODING_SPEC_ACTION_PTR == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK)))
  {
    *ppDest = mcuxClKey_getKeyData(key);
  }
  else if(MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_keyUnwrapRfc3394));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_keyUnwrapRfc3394(session, key));
    *ppDest = mcuxClAes_getKeyDest_rfc3394UnWrap();
  }
  else
  {
    /* spec is not valid */
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }

  if(pKeyChecksums != NULL)
  {
    pKeyChecksums->VerifyFunc = key->encoding->handleKeyChecksumsFunc;
    pKeyChecksums->protectionToken_VerifyFunc = key->encoding->protectionToken_handleKeyChecksumsFunc;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_keyLoad_rfc3394);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_keyStore_rfc3394, mcuxClKey_StoreFuncPtr_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_keyStore_rfc3394(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  const uint8_t *pSrc,
  mcuxClKey_Encoding_Spec_t spec)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_keyStore_rfc3394);

  /* If spec specifies to set the key pointer to pSrc */
  if(MCUXCLKEY_ENCODING_SPEC_ACTION_PTR == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("pKeyData can not made const inside of key component as it is possible that the data changes after init due to generation/agreement/derivation of keys.");
    mcuxClKey_setKeyData(key, (uint8_t *) pSrc);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
  }
  else if(MCUXCLKEY_ENCODING_SPEC_ACTION_STORE_FROM_PLAIN == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    /* For a plain key the `pSfrSeed` is set to NULL. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_keyWrapRfc3394));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
      mcuxClSgi_Utils_keyWrapRfc3394(session, key, pSrc, NULL /* pSrc is plain key material */)
    );
  }
  else if(MCUXCLKEY_ENCODING_SPEC_ACTION_STORE_FROM_PROTECTED == (spec & MCUXCLKEY_ENCODING_SPEC_ACTION_MASK))
  {
    const uint8_t* pMaskedKeyMaterial = pSrc;

    /* The SFR seed is stored after the plain key, which has the length of type.size */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pSrc is always 32 bit aligned as it is an SGI SFR, key->type.size is a multiple of 4, i.e. &pSrc[key->type.size] is 32 bit aligned");
    const uint32_t* pSfrSeed = (const uint32_t*)(&pSrc[key->type.size]);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING();

    /* For a protected key the `pSfrSeed` is passed to the wrapping function. */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_keyWrapRfc3394));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_keyWrapRfc3394(session, key, pMaskedKeyMaterial, pSfrSeed));
  }
  else
  {
    /* spec is not valid */
    MCUXCLSESSION_FAULT(session, MCUXCLKEY_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_keyStore_rfc3394);
}

/**
 * @brief RFC3394 encoded key load function. This function will place the encoded key
 *        in SGI registers in preparation for unwrapping operations.
 *
 * @param[in]     wrappedKey  Initialized key handle containing wrapped key.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_rfc3394Utils_loadWrappedKeyData)
static MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_rfc3394Utils_loadWrappedKeyData(mcuxClKey_Handle_t wrappedKey)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_rfc3394Utils_loadWrappedKeyData);

  /*************************************************************************************
  *  SGI Register layout at the end of LoadWrappedKeyData execution.
  *
  *    DATIN_0                         | ... | DATIN_n-1                         |
  *  -----------------------------------------------------------------------------
  *  | 0000000000000000 WrappedKey[n]  | ... | 0000000000000000 WrappedKey[1]    |
  *
  *  Order of wrapped RFC3394 key blocks in DATIN registers is reversed such that main
  *  processing loop starts at index 0.
  *
  *    DATOUT                            |
  *  -------------------------------------
  *  | WrappedKey[0]  xxxxxxxxxxxxxxxx   |
  *
  *  n - index [0:n] of RFC3394 wrapped data block
  *  x - uninitialized
  *  0 - cleared
  **************************************************************************************/

  /* Fill DATOUT lower part */
  uint8_t *pData = mcuxClKey_getKeyData(wrappedKey);
  uint8_t *pTargetReg = (uint8_t*)mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
  MCUX_CSSL_DI_RECORD(memory_copy_words_params, pTargetReg);
  MCUX_CSSL_DI_RECORD(memory_copy_words_params, pData);
  MCUX_CSSL_DI_RECORD(memory_copy_words_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pTargetReg, pData, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE));

  /* Fill corresponding DATIN parts based on the key size. */
  /* Loop iterations start with storing lowest wrapped key data chunk into the highest DATIN register*/
  const uint32_t keySizeInRfc3394Blocks = mcuxClKey_getSize(wrappedKey) / MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;

  for(int i = (int)keySizeInRfc3394Blocks - 1; i >= 0; --i)
  {
    pData += MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
    pTargetReg = (uint8_t*)mcuxClSgi_Drv_getAddr(mcuxClSgi_Drv_datinIndexToOffset((uint32_t)i));
    MCUX_CSSL_DI_RECORD(memory_clear_loop_params, pTargetReg);
    MCUX_CSSL_DI_RECORD(memory_clear_loop_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(pTargetReg, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE));
    pTargetReg += MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, pTargetReg);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, pData);
    MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_words_int_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_words_int));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_words_int(pTargetReg, pData, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE));
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_rfc3394Utils_loadWrappedKeyData);
}

/**
 * @brief Key unwrap function as specified in RFC3394 using software algorithm
 *        in combination with SGI AES block decrypt operations.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_keyUnwrapRfc3394_swDriven)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_keyUnwrapRfc3394_swDriven(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t wrappedKey,
  uint32_t *pKeyDst)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_keyUnwrapRfc3394_swDriven);

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_rfc3394Utils_loadWrappedKeyData));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_rfc3394Utils_loadWrappedKeyData(wrappedKey));

  /* Get parameters of already loaded key-wrapping key (KWK) */
  const mcuxClKey_Descriptor_t *keyWrappingKey = mcuxClKey_getKeyDescriptorFromAuxData(wrappedKey);

  const uint32_t jCount = 6U; /* Number of external loop iterations according to RFC3394 unwrap algorithm */
  const uint32_t iCount = mcuxClKey_getSize(wrappedKey) / MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
  /* t factor to be used within the loop
  *  For first loop iteration according to RFC3394 we can calculate:
  *  t = n*j+i = n*j + n = n*(j+1) = n*6 ==> iCount*jCount */
  uint32_t t = jCount * iCount;

  uint32_t sgiCtrlKey = mcuxClSgi_getKeyConf(keyWrappingKey);
  uint32_t *pResult = mcuxClSgi_Drv_getAddr(MCUXCLSGI_DRV_DATOUT_OFFSET);
  uint32_t *pLowerResultWord = pResult + (MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE >> 2U);
  uint8_t *pLowerResult = (uint8_t*)pLowerResultWord;

  /*******************************************************************************
  * Loops below implement key unwrap RFC3394 algorithm using index based approach
  * One loop iteration (j,i):
  *
  *                          DATIN_i
  *           --------------------------------------
  *           |               t |      R[i]        |
  *           --------------------------------------
  *                             |
  *                             V
  *                            XOR        <-------------
  *           --------------------------------------   |
  *           |     A xor t     |      R[i]        |   |
  *           --------------------------------------   |
  *                             |                      |
  *                             V                      |
  *                          DECRYPT                   |
  *                             |                      |
  *                             V                      |
  *                          DATOUT                    |
  *           --------------------------------------   |
  *           |       A         |        0         |----
  *           --------------------------------------
  ********************************************************************************/

  /* Point to the end of data buffer (wrt. size of unwrapped key),
     unwrapped key will be stored blockwise starting from the right-side */
  uint32_t *pCopyOut = pKeyDst + ((iCount * MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE)>>2U);

  /* Generate seed for SFR masking */
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPrng_generate_word));
  MCUX_CSSL_FP_FUNCTION_CALL(sfrSeed, mcuxClPrng_generate_word());

  for(uint32_t j = 0U; j < jCount; ++j)
  {
    for(uint32_t i = 0U; i < iCount; ++i)
    {
      /* Set t in the first half of DATIN (starting from the right side of first half as per RFC3349) */
      mcuxClSgi_Drv_loadWord(mcuxClSgi_Drv_datinIndexToOffset(i) + sizeof(uint32_t), MCUXCLMEMORY_SWITCH_4BYTE_ENDIANNESS(t));

      MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_params, pLowerResult);
      MCUX_CSSL_DI_RECORD(mcuxClMemory_clear_int_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear_int));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear_int(pLowerResult, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE));

      /* Execute decrypt with DATIN_i xor DATOUT as input */
      /* Each internal (iCount) loop iteration shall use seaprate DATIN slot to minimize number of copy operations
         needed for storing intermediate data in between the loop iterations */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_start));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_start(
        MCUXCLSGI_DRV_CTRL_END_UP                             |
        MCUXCLSGI_DRV_CTRL_DEC                                |
        MCUXCLSGI_DRV_CTRL_INSEL_XOR_DATOUT_NUMBER_TO_CTRL(i) |
        MCUXCLSGI_DRV_CTRL_OUTSEL_RES                         |
        sgiCtrlKey
      ));

      /* Wait for result before copy out */
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_wait));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_wait());

      if((jCount - 1U) != j)
      {
        /* Store second half of result (R[i]) in corresponding DATIN register for next external loop iteration */
        uint8_t *pLowerResultStore = (uint8_t *)mcuxClSgi_Drv_getAddr(mcuxClSgi_Drv_datinIndexToOffset(i)) + MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
        MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_params, pLowerResultStore);
        MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_params, pLowerResult);
        MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int(pLowerResultStore, pLowerResult, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE));
      }
      else
      {
        /* Store second half of result (R[i]) in the result buffer */
        /* Note: The `sfrSeed` is re-initialized for each block, and the SFR protected unwrapped key is copied to the `pKeyDst`.*/
        pCopyOut -= (MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE >> 2U);
        MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
        MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pLowerResultWord);
        MCUX_CSSL_DI_RECORD(mcuxClSgi_Utils_copySfrMasked_params, pCopyOut);
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_copySfrMasked));
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_copySfrMasked(pCopyOut, pLowerResultWord, MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE, sfrSeed));
      }

      /* RFC3394 t = n * j + i calculation equivalent */
      /* The inner loop is executed jCount * iCount times, which is equal to the initialization value of t, i.e. t = 1 before the last decrement */
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER_VOID(t, 1U, jCount * iCount)
      --t;
    }
  }

  /* Check if unwrapped IV matches the reference IV consisting of
     0xA6 bytes of MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE length */
  const uint32_t referenceIvWord = 0xA6A6A6A6U;
  if(   (referenceIvWord != mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 0U))
     || (referenceIvWord != mcuxClSgi_Drv_storeWord(MCUXCLSGI_DRV_DATOUT_OFFSET + 4U)))
  {
    /* Clear the result in case validation fails - No need to balance DI or FP in error cases */
    (void) mcuxClMemory_clear_int((uint8_t*)pCopyOut, iCount * MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE);
    MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  /* Store the sfrSeed after the SFR-masked plain key */
  uint32_t *pSfrMaskSeed = (&pKeyDst[(wrappedKey->type.size)>>2U]);
  *pSfrMaskSeed = sfrSeed;

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_keyUnwrapRfc3394_swDriven);
}

/* Flush function for AES keys */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAes_keyFlush, mcuxClKey_FlushFuncPtr_t)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClAes_keyFlush(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClKey_Handle_t key,
  mcuxClKey_Encoding_Spec_t spec UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAes_keyFlush);

  /* AES keys are assumed to be in SGI */

  uint32_t keySlot = mcuxClKey_getLoadedKeySlot(key);
  if(keySlot >= MCUXCLSGI_DRV_KEY_BANK_COUNT)
  {
    /* Key slot number does not exist in SGI - invalid key object */
    MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
  }

  uint32_t numKeyWords = mcuxClKey_getSize(key) / sizeof(uint32_t);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_flushRegisterBanks));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_flushRegisterBanks(mcuxClSgi_Drv_keySlotToOffset(keySlot), numKeyWords));

  /* Restrore the initial state of the key object */
  mcuxClKey_setLoadStatus(key, MCUXCLKEY_LOADSTATUS_NOTLOADED);
  mcuxClKey_setLoadedKeySlot(key, MCUXCLKEY_LOADOPTION_SLOT_INVALID);

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClAes_keyFlush);
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()



/**
 * @brief Key encoding descriptor for RFC3394 key wrap/unwrap.
 */
const mcuxClKey_EncodingDescriptor_t mcuxClAes_EncodingDescriptor_Rfc3394 = {
  .loadFunc = mcuxClAes_keyLoad_rfc3394,
  .storeFunc = mcuxClAes_keyStore_rfc3394,
  .flushFunc = mcuxClAes_keyFlush,
  .handleKeyChecksumsFunc = mcuxClKey_handleKeyChecksums_none,
  .protectionToken_loadFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_keyLoad_rfc3394),
  .protectionToken_storeFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_keyStore_rfc3394),
  .protectionToken_flushFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_keyFlush),
  .protectionToken_handleKeyChecksumsFunc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_handleKeyChecksums_none)
};

MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
