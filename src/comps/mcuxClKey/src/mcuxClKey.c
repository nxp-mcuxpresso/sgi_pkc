/*--------------------------------------------------------------------------*/
/* Copyright 2020-2025 NXP                                                  */
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

/** @file  mcuxClKey.c
 *  @brief Implementation of the Key component to deal with keys used by
 *  higher-level components. This file implements the functions declared in
 *  mcuxClKey.h. */

#include <mcuxClKey.h>
#include <mcuxClMemory.h>
#include <mcuxClToolchain.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClMemory_ClearSecure_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <mcuxClAes_KeyEncodingMechanisms.h>
#include <internal/mcuxClAes_KeyEncodingMechanisms_Sgi.h>
#include <internal/mcuxClAes_Internal_Functions.h>
#include <internal/mcuxClSgi_Drv.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_init(
    mcuxClSession_Handle_t session UNUSED_PARAM,
    mcuxClKey_Handle_t key,
    mcuxClKey_Type_t type,
    const uint8_t * pKeyData,
    uint32_t keyDataLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_init);

    /* Fill key structure */
    mcuxClKey_setTypeDescriptor(key, *type);
    mcuxClKey_setEncodingType(key, type->plainEncoding);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("pKeyData can not made const inside of key component as it is possible that the data changes after init due to generation/agreement/derivation of keys.");
    mcuxClKey_setKeyData(key, (uint8_t *)pKeyData);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER();
    mcuxClKey_setKeyContainerSize(key, keyDataLength);
    mcuxClKey_setKeyContainerUsedSize(key, keyDataLength);
    mcuxClKey_setLoadedKeySlot(key, MCUXCLKEY_LOADOPTION_SLOT_INVALID);
    mcuxClKey_setLoadStatus(key, MCUXCLKEY_LOADSTATUS_NOTLOADED);
    mcuxClKey_setLinkedData(key, NULL);
    mcuxClKey_setParentKey(key, NULL);

    /* Check if this is a variable-length external HMAC key */
    if(0u == type->size)
    {
        /* Overwrite the type's size with the given one */
        key->type.size = keyDataLength;
    }

    if(NULL != pKeyData)
    {
        /* key data size validation in case of symmetric keys,
           there are instances where encoded key has bigger size than the base type, therefore check is ">" */
        if(((key->type.algoId & MCUXCLKEY_ALGO_ID_USAGE_MASK) == MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY) && (key->type.size > keyDataLength))
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_init, MCUXCLKEY_STATUS_INVALID_INPUT);
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClKey_init, MCUXCLKEY_STATUS_OK, MCUXCLKEY_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setEncoding)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_setEncoding(
    mcuxClSession_Handle_t session UNUSED_PARAM,
    mcuxClKey_Handle_t key,
    mcuxClKey_Encoding_t encoding,
    const uint8_t * pAuxData,
    uint32_t auxDataLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_setEncoding);

    /* Fill key structure */
    mcuxClKey_setEncodingType(key, encoding);
    mcuxClKey_setAuxData(key, pAuxData);
    mcuxClKey_setAuxDataLength(key, auxDataLength);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClKey_setEncoding, MCUXCLKEY_STATUS_OK, MCUXCLKEY_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_encode)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_encode(
    mcuxClSession_Handle_t session,
    mcuxClKey_Encoding_t encoding,
    mcuxClKey_Handle_t encodedKey,
    mcuxClKey_Type_t type,
    const uint8_t * pPlainKeyData,
    uint32_t plainKeyDataLength,
    const uint8_t * pAuxData,
    uint32_t auxDataLength,
    uint8_t * pEncodedKeyData,
    uint32_t * const pEncodedKeyDataLength
)
{
    MCUXCLSESSION_ENTRY(session, mcuxClKey_encode, diRefValue, MCUXCLKEY_STATUS_FAULT_ATTACK);

    /* Only AES key encoding mechanisms implemented so far. Early return to avoid set-up of the key object. */
    if(MCUXCLKEY_ALGO_ID_AES != (type->algoId & MCUXCLKEY_ALGO_ID_ALGO_MASK))
    {
        /* key type not supported (yet) for encoding */
        MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
    }

    /**
     *  1. Initialize the new key object with basic fields for Key_load
     */
    mcuxClKey_setTypeDescriptor(encodedKey, *type);
    mcuxClKey_setLoadedKeySlot(encodedKey, MCUXCLKEY_LOADOPTION_SLOT_INVALID);
    mcuxClKey_setLoadStatus(encodedKey, MCUXCLKEY_LOADSTATUS_NOTLOADED);
    mcuxClKey_setLinkedData(encodedKey, NULL);
    mcuxClKey_setParentKey(encodedKey, NULL);
    mcuxClKey_setAuxData(encodedKey, (const uint8_t *)pAuxData);
    mcuxClKey_setAuxDataLength(encodedKey, auxDataLength);

    /* Check if this is a variable-length external HMAC key */
    if(0u == type->size)
    {
        /* Overwrite the type's size with the given one */
        encodedKey->type.size = plainKeyDataLength;
    }

    if(NULL != pPlainKeyData)
    {
        /* key data size validation in case of symmetric keys*/
        if(((encodedKey->type.algoId & MCUXCLKEY_ALGO_ID_USAGE_MASK) == MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY) && (encodedKey->type.size != plainKeyDataLength))
        {
            MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
        }
    }

    /**
     *  2. Call Key_load to load the plain key
     */

    /* Initialize fields for the plain encoding before calling Key_Load */
    mcuxClKey_setEncodingType(encodedKey, type->plainEncoding);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("pKeyData can not made const inside of key component as it is possible that the data changes after init due to generation/agreement/derivation of keys.");
    mcuxClKey_setKeyData(encodedKey, (uint8_t *)pPlainKeyData);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER();
    mcuxClKey_setKeyContainerSize(encodedKey, plainKeyDataLength);
    mcuxClKey_setKeyContainerUsedSize(encodedKey, plainKeyDataLength);

    /* Parameters for the plain key load - to be set encoding dependent */
    uint8_t *pPlainKeyDest = NULL;
    mcuxClKey_Encoding_Spec_t spec = MCUXCLKEY_ENCODING_SPEC_ACTION_SECURE;

    /* Only AES key encoding mechanisms implemented so far */
    if(MCUXCLKEY_ALGO_ID_AES == (type->algoId & MCUXCLKEY_ALGO_ID_ALGO_MASK))
    {
        if(mcuxClAes_Encoding_Rfc3394 == encoding)
        {
            /* For Rfc3394 encoding, do not load the key but just receive the pointer to it.
             * The SGI-driven Rfc3394 wrap has to load the key after starting the SGI. */
            spec = MCUXCLKEY_ENCODING_SPEC_ACTION_PTR;
        }
        else
        {
            pPlainKeyDest = mcuxClAes_getKeyDest_default();
        }
    }
    else
    {
        /* key type not supported (yet) for encoding */
        MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
    }

    /* Securely load the plain key material */
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_load));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_load(session, encodedKey, &pPlainKeyDest, NULL /* pKeyChecksums */, spec));

    /**
     *  3. Modify the key object to the new encoding
     */
    mcuxClKey_setEncodingType(encodedKey, encoding);
    mcuxClKey_setKeyData(encodedKey, pEncodedKeyData);
    // TODO CLNS-16429: how to best set the container.length and container.used? Should pEncodedKeyDataLength be an input parameter instead, as for Key_init?

    /**
     *  4. Perform key storing, this will apply the encoding and store the encoded key material in the container.
     */
    uint8_t *pPlainKeySrc = pPlainKeyDest;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_store));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_store(session, encodedKey, pPlainKeySrc, MCUXCLKEY_ENCODING_SPEC_ACTION_STORE_FROM_PLAIN));

    /**
     * 5. Set *pEncodedKeyDataLength to number of bytes written to pEncodedKeyData
     */
    if (mcuxClAes_Encoding_Rfc3394 == encoding)
    {
      uint32_t keySize = mcuxClKey_getSize(encodedKey);
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(keySize, 0U, MCUXCLAES_AES256_KEY_SIZE, MCUXCLKEY_STATUS_FAULT_ATTACK)
      // TODO CLNS-16429
      *pEncodedKeyDataLength = keySize + MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
    }

    MCUXCLSESSION_EXIT(session, mcuxClKey_encode, diRefValue, MCUXCLKEY_STATUS_OK, MCUXCLKEY_STATUS_FAULT_ATTACK);
}

/* Init the recodedKey object, decode/load the encodedKey, recode the key material */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_recode)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_recode(
    mcuxClSession_Handle_t session,
    mcuxClKey_Handle_t encodedKey, // in
    mcuxClKey_Encoding_t encoding,
    mcuxClKey_Handle_t recodedKey, // out
    const uint8_t * pAuxData,
    uint32_t auxDataLength,
    uint8_t * pEncodedKeyData,
    uint32_t * const pEncodedKeyDataLength
)
{
    MCUXCLSESSION_ENTRY(session, mcuxClKey_recode, diRefValue, MCUXCLKEY_STATUS_FAULT_ATTACK);

    /* Only AES key encoding mechanisms implemented so far. Early return to avoid set-up of the key object. */
    if(MCUXCLKEY_ALGO_ID_AES != (encodedKey->type.algoId & MCUXCLKEY_ALGO_ID_ALGO_MASK))
    {
        /* key type not supported (yet) for encoding */
        MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
    }

    /* 1. Initialize the new key object with basic fields for Key_load */
    mcuxClKey_setTypeDescriptor(recodedKey, encodedKey->type);
    mcuxClKey_setLoadedKeySlot(recodedKey, MCUXCLKEY_LOADOPTION_SLOT_INVALID);
    mcuxClKey_setLoadStatus(recodedKey, MCUXCLKEY_LOADSTATUS_NOTLOADED);
    mcuxClKey_setLinkedData(recodedKey, NULL);
    mcuxClKey_setParentKey(recodedKey, NULL);
    mcuxClKey_setAuxData(recodedKey, (const uint8_t *)pAuxData);
    mcuxClKey_setAuxDataLength(recodedKey, auxDataLength);
    mcuxClKey_setEncodingType(recodedKey, encoding);
    mcuxClKey_setKeyData(recodedKey, pEncodedKeyData);
    // TODO CLNS-16429: how to best set the container.length and container.used? Should pEncodedKeyDataLength be an input parameter instead, as for Key_init?

    uint8_t *pPlainKeyDest = NULL;

    if(mcuxClAes_Encoding_Rfc3394 == encoding)
    {
      /* Track the location/destination of the key, similar behaviour as mcuxClKey_load.*/
      pPlainKeyDest = mcuxClKey_getKeyData(recodedKey);

      /* Call the SW-driven unwrap for the wrapped key.
       * The result of this operation is the unwrapped key material in pPlainKeyDest */
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Customer guidance include a 32-bit aligned key data.")

      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_keyUnwrapRfc3394_swDriven));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_keyUnwrapRfc3394_swDriven(session, encodedKey, (uint32_t *)pPlainKeyDest));
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    }
    else
    {
        /* key type not supported (yet) for recoding */
        /* TODO: Call mcuxClKey_load for other encoding, e.g. protections? Similarly to Key_encode */
        MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
    }

    /* 3. Perform key storing, this will apply the new encoding and store the encoded key material in the container */
    uint8_t *pPlainKeySrc = pPlainKeyDest;
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_store));
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_store(session, recodedKey, pPlainKeySrc, MCUXCLKEY_ENCODING_SPEC_ACTION_STORE_FROM_PROTECTED));

    /* 4. Set *pEncodedKeyDataLength to number of bytes written to pEncodedKeyData */
    /* In case of mcuxClAes_Encoding_Rfc3394 encoding, the result size is the key material size + 8 bytes (MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE). */
    if (mcuxClAes_Encoding_Rfc3394 == encoding)
    {
      uint32_t keySize = mcuxClKey_getSize(encodedKey);
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(keySize, 0U, MCUXCLAES_AES256_KEY_SIZE, MCUXCLKEY_STATUS_FAULT_ATTACK)
      // TODO CLNS-16429
      *pEncodedKeyDataLength = keySize + MCUXCLAES_ENCODING_RFC3394_BLOCK_SIZE;
    }

    MCUXCLSESSION_EXIT(session, mcuxClKey_recode, diRefValue, MCUXCLKEY_STATUS_OK, MCUXCLKEY_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_loadCopro)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_loadCopro(
    mcuxClSession_Handle_t session,
    mcuxClKey_Handle_t key,
    uint32_t loadOptions // slot and other options
)
{
    MCUXCLSESSION_ENTRY(session, mcuxClKey_loadCopro, diRefValue, MCUXCLKEY_STATUS_FAULT_ATTACK);

    if(MCUXCLKEY_LOADSTATUS_LOCATION_COPRO == (mcuxClKey_getLoadedKeySlot(key) & MCUXCLKEY_LOADSTATUS_LOCATION_MASK))
    {
      /* If the key was already loaded to a copro before, flush the old location before continuing
       * with the new load operation. */
       MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush_internal));
       MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_flush_internal(session, key, 0U /* spec */));
    }

    /* Get the slot to load to from the given loadOptions */
    uint32_t slot = (loadOptions & MCUXCLKEY_LOADOPTION_SLOT_SLOT_MASK) >> MCUXCLKEY_LOADOPTION_SLOT_SLOT_SHIFT;

    /* Load the key to the respective copro, based on the key type */
    if(MCUXCLKEY_ALGO_ID_AES == (mcuxClKey_getAlgoId(key) & MCUXCLKEY_ALGO_ID_ALGO_MASK))
    {
        if(MCUXCLKEY_LOADOPTION_SLOT_COPRO_SGI != (loadOptions & MCUXCLKEY_LOADOPTION_SLOT_COPRO_MASK))
        {
          /* Not a proper SGI key load option */
          MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
        }

        if(MCUXCLKEY_LOADOPTION_ALREADYLOADED != (loadOptions & MCUXCLKEY_LOADOPTION_ALREADYLOADED_MASK))
        {
            /* Initialize the SGI to LE before loading the key */
            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_init));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_init(MCUXCLSGI_DRV_BYTE_ORDER_LE));

            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAes_loadKey_Sgi));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClAes_loadKey_Sgi(session, key, NULL /* Workarea */, mcuxClSgi_Drv_keySlotToOffset(slot)));

            MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Drv_close));
            MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Drv_close(session));
        }

        uint16_t loadStatusDetails = 0U;
        if(mcuxClSgi_Drv_isWriteOnlyKeySlot(slot))
        {
            loadStatusDetails = MCUXCLKEY_LOADSTATUS_OPTIONS_WRITEONLY;
        }
        mcuxClKey_setLoadStatus(key, MCUXCLKEY_LOADSTATUS_LOCATION_COPRO | MCUXCLKEY_LOADSTATUS_OPTIONS_KEEPLOADED | loadStatusDetails);
    }
    else
    {
        /* key type not supported (yet) for preloading to a key slot */
        MCUXCLSESSION_ERROR(session, MCUXCLKEY_STATUS_INVALID_INPUT);
    }

    mcuxClKey_setLoadedKeySlot(key, slot);

    MCUXCLSESSION_EXIT(session, mcuxClKey_loadCopro, diRefValue, MCUXCLKEY_STATUS_OK, MCUXCLKEY_STATUS_FAULT_ATTACK);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_linkKeyPair)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClKey_linkKeyPair(
    mcuxClSession_Handle_t session  UNUSED_PARAM,
    mcuxClKey_Handle_t privKey,
    mcuxClKey_Handle_t pubKey)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_linkKeyPair);

    /* Link key pair handles */
    mcuxClKey_setLinkedData(privKey, (void *) pubKey);
    mcuxClKey_setLinkedData(pubKey, (void *) privKey);

    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClKey_linkKeyPair);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_flush)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_flush(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key
)
{
  MCUXCLSESSION_ENTRY(session, mcuxClKey_flush, diRefValue, MCUXCLKEY_STATUS_FAULT_ATTACK);
  MCUX_CSSL_FP_EXPECT(
      MCUX_CSSL_FP_CONDITIONAL((MCUXCLKEY_LOADSTATUS_LOCATION_COPRO == (mcuxClKey_getLoadStatus(key) & (MCUXCLKEY_LOADSTATUS_LOCATION_COPRO))),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush_internal))
  );

  // TODO CLNS-16197: How to keep consistency with "linked" key objects?

  mcuxClKey_LoadStatus_t loadStatus = mcuxClKey_getLoadStatus(key);
  if(MCUXCLKEY_LOADSTATUS_LOCATION_COPRO == (loadStatus & MCUXCLKEY_LOADSTATUS_LOCATION_MASK))
  {
    /* If the key is loaded to a HW IP, flush the key from its location and reset the loadstatus on successful flush
     * (happens in mcuxClKey_flush_internal) */
    // TODO CLNS-16429: which size in the key object is the best to use for flushing? Key->type.size for single part keys/sym keys, but how to deal keys with multiple parts?
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClKey_flush_internal(session, key, 0U /* spec */));
  }

  /* Nothing to do - key is not loaded */
  MCUXCLSESSION_EXIT(session, mcuxClKey_flush, diRefValue, MCUXCLKEY_STATUS_OK, MCUXCLKEY_STATUS_FAULT_ATTACK);
}
