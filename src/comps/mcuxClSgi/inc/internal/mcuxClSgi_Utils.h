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

#ifndef MCUXCLSGI_UTILS_H_
#define MCUXCLSGI_UTILS_H_

#include <mcuxClCore_Platform.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClSgi_Drv.h>
#include <mcuxClSgi_Types.h>
#include <mcuxClSession.h>
#include <mcuxClKey_Types.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>

#include <mcuxClBuffer.h>
#include <mcuxCsslDataIntegrity.h>
#include <internal/mcuxClMemory_CopySecure_Internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************
 * Type declarations
 **********************************************************/

/**
 * @brief Function type to initialize the SGI for the respective hash algorithm
 *
 * This function initializes the SGI to perform a hash operation of dedicated algorithm in dedicated mode using either a standard or specified IV
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClSgi_Utils_initHash,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClSgi_Utils_initHash)(
  const uint32_t *pIV,
  uint32_t mode
));

/**
 * @brief Function type to load one block of internal input data to the SGI
 *
 * This function loads one word-aligned block of internal input data, of size dedicated to chosen hash algorithm, to the SGI
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClSgi_Utils_loadInternalHashBlock,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClSgi_Utils_loadInternalHashBlock)(
  const uint32_t *pData
));

/**
 * @brief Function type to load one block of external input data to the SGI
 *
 * This function loads one block of external input data, of size dedicated to chosen hash algorithm, to the SGI
 *
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClSgi_Utils_loadExternalHashBlock,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClSgi_Utils_loadExternalHashBlock)(
  mcuxClSession_Handle_t session,
  mcuxCl_InputBuffer_t dataBuf,
  uint32_t offset
));

/*****************************************************
 * utilHash Functions
 *****************************************************/

#define MCUXCLSGI_UTILS_AUTO_MODE_LOAD_IV           (0xA5A5B4B4u)
#define MCUXCLSGI_UTILS_NORMAL_MODE_LOAD_IV         (0xA5A54B4Bu)
#define MCUXCLSGI_UTILS_AUTO_MODE_STANDARD_IV       (0x5A5AB4B4u)
#define MCUXCLSGI_UTILS_NORMAL_MODE_STANDARD_IV     (0x5A5A4B4Bu)

/**
 * @brief Initializes SHA-224 based on provided mode parameters
 *
 * This function initializes SHA-224 based on provided user choices,
 * namely running SGI in NORMAL or AUTO mode and loading an IV which is
 * provided by the user, or using the standard IV
 *
 * @param[in]  pIV    Pointer to data buffer which is loaded
 *                    (in case of using the standard IV, please set to NULL)
 * @param[in]  mode   Chooses, whether to use AUTO or NORMAL mode and whether
 *                    to use the standard IV or load an IV
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_initSha224, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha224(const uint32_t *pIV, uint32_t mode);

/**
 * @brief Initializes SHA-256 based on provided mode parameters
 *
 * This function initializes SHA-256 based on provided user choices,
 * namely running SGI in NORMAL or AUTO mode and loading an IV which is
 * provided by the user, or using the standard IV
 *
 * @param[in]  pIV    Pointer to data buffer which is loaded
 *                    (in case of using the standard IV, please set to NULL)
 * @param[in]  mode   Chooses, whether to use AUTO or NORMAL mode and whether
 *                    to use the standard IV or load an IV
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_initSha256, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha256(const uint32_t *pIV, uint32_t mode);

/**
 * @brief Initializes SHA-384 based on provided mode parameters
 *
 * This function initializes SHA-384 based on provided user choices,
 * namely running SGI in NORMAL or AUTO mode and loading an IV which is
 * provided by the user, or using the standard IV
 *
 * @param[in]  pIV    Pointer to data buffer which is loaded
 *                    (in case of using the standard IV, please set to NULL)
 * @param[in]  mode   Chooses, whether to use AUTO or NORMAL mode and whether
 *                    to use the standard IV or load an IV
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_initSha384, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha384(const uint32_t *pIV, uint32_t mode);

/**
 * @brief Initializes SHA-512 based on provided mode parameters
 *
 * This function initializes SHA-512 based on provided user choices,
 * namely running SGI in NORMAL or AUTO mode and loading an IV which is
 * provided by the user, or using the standard IV
 *
 * @param[in]  pIV    Pointer to data buffer which is loaded
 *                    (in case of using the standard IV, please set to NULL)
 * @param[in]  mode   Chooses, whether to use AUTO or NORMAL mode and whether
 *                    to use the standard IV or load an IV
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_initSha512, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha512(const uint32_t *pIV, uint32_t mode);

/**
 * @brief Initializes SHA-512/224 based on provided mode parameters
 *
 * This function initializes SHA-512/224 based on provided user choices,
 * namely running SGI in NORMAL or AUTO mode and loading an IV which is
 * provided by the user, or using the standard IV
 *
 * @param[in]  pIV    Pointer to data buffer which is loaded
 *                    (in case of using the standard IV, please set to NULL)
 * @param[in]  mode   Chooses, whether to use AUTO or NORMAL mode and whether
 *                    to use the standard IV or load an IV
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_initSha512_224, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha512_224(const uint32_t *pIV, uint32_t mode);

/**
 * @brief Initializes SHA-512/256 based on provided mode parameters
 *
 * This function initializes SHA-512/256 based on provided user choices,
 * namely running SGI in NORMAL or AUTO mode and loading an IV which is
 * provided by the user, or using the standard IV
 *
 * @param[in]  pIV    Pointer to data buffer which is loaded
 *                    (in case of using the standard IV, please set to NULL)
 * @param[in]  mode   Chooses, whether to use AUTO or NORMAL mode and whether
 *                    to use the standard IV or load an IV
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_initSha512_256, mcuxClSgi_Utils_initHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_initSha512_256(const uint32_t *pIV, uint32_t mode);

/**
 * @brief Returns the key type sgi configuration of the key handle.
 *
 * @return Sgi key type configuration field of the key handle.
 *         #MCUXCLSGI_DRV_CTRL_INVALID on invalid key handle
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_getKeyTypeConf)
static inline uint32_t mcuxClSgi_getKeyTypeConf(const mcuxClKey_Descriptor_t* key)
{
  uint32_t keyTypeConfig = MCUXCLSGI_DRV_CTRL_INVALID;
  if(MCUXCLKEY_ALGO_ID_AES == (key->type.algoId & MCUXCLKEY_ALGO_ID_ALGO_MASK))
  {
    switch(key->type.size)
    {
      case MCUXCLKEY_SIZE_128:
        keyTypeConfig = MCUXCLSGI_DRV_CTRL_AES128;
        break;
      case MCUXCLKEY_SIZE_192:
        keyTypeConfig = MCUXCLSGI_DRV_CTRL_AES192;
        break;
      case MCUXCLKEY_SIZE_256:
        keyTypeConfig = MCUXCLSGI_DRV_CTRL_AES256;
        break;
      default:
        keyTypeConfig = MCUXCLSGI_DRV_CTRL_INVALID;
        break;
    }
  }

  return keyTypeConfig;
}

/**
 * @brief Returns the sgi configuration of the key handle.
 *
 * @return Sgi configuration field of the key handle.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_getKeyConf)
static inline uint32_t mcuxClSgi_getKeyConf(const mcuxClKey_Descriptor_t* key)
{
  uint32_t keyTypeConfig = mcuxClSgi_getKeyTypeConf(key);
  uint32_t keyIndex = mcuxClSgi_Drv_keySlotToIndex(mcuxClKey_getLoadedKeySlot(key));
  return keyTypeConfig | MCUXCLSGI_DRV_CTRL_INKEYSEL(keyIndex);
}

/**
 * @brief Loads a 128-bit block of data to the SGI
 *
 * This function loads a 128-bit data block to the specified SGI
 * register bank. Unaligned access is handled properly, as
 * well as differences in compilers and architectures.
 *
 * Data Integrity: Expunge(mcuxClSgi_Drv_getAddr(sgisfrDatOffset) + pData + 16u)
 *
 * @param[in]  sgisfrDatOffset   Offset of the target SGI SFR,
 *                               can be either of these values:
 *                                 #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                                 #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in]  pData             Pointer to data buffer which is loaded
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_load128BitBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load128BitBlock(uint32_t sgisfrDatOffset, const uint8_t *pData);

/** Helper macro for DI balanced call to mcuxClSgi_Utils_load128BitBlock. */
#define MCUXCLSGI_UTILS_LOAD128BITBLOCK_DI_BALANCED(sfrDatOffset, pData) \
  do {  \
    MCUX_CSSL_DI_RECORD(sgiLoad, ((uint32_t)mcuxClSgi_Drv_getAddr(sfrDatOffset)) + ((uint32_t)pData) + 16u); \
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_load128BitBlock)); \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_load128BitBlock(sfrDatOffset, pData)); \
  } while(false)

/**
 * @brief Loads a data to the SGI which are not full block
 *
 * This function loads a data to the specified SGI
 * register bank. Unaligned access is handled properly, as
 * well as differences in compilers and architectures.
 *
 * Data Integrity: Expunge(mcuxClSgi_Drv_getAddr(sgisfrDatOffset) + pData + len + pTempBuff)
 *
 * @param[in]  sgisfrDatOffset   Offset of the target SGI SFR,
 *                               can be either of these values:
 *                                 #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                                 #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in]  pData             Pointer to data buffer which is loaded
 * @param[in]  len               Length of input data
 * @param[in]  pTempBuff         Pointer to temporary buffer
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_load_notFull128Block_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load_notFull128Block_buffer(uint32_t sgisfrDatOffset, mcuxCl_InputBuffer_t pData, uint32_t len, uint8_t *pTempBuff);
/**
 * @brief Loads a 128-bit block of data to the SGI
 *
 * This function loads a 128-bit data block to the specified SGI
 * register bank.
 *
 * SREQI_BCIPHER_1 - Use this function for data copy from user input to SGI.
 *
 * Data Integrity: Expunge(mcuxClSgi_Drv_getAddr(sgisfrDatOffset) + dataBuf + offset + 16)
 *
 * @param[in]  sgisfrDatOffset   Offset of the target SGI SFR,
 *                               can be either of these values:
 *                                 #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                                 #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in]  dataBuf           Data buffer which from which data is loaded
 * @param[in]  offset            Offset of data buffer from which data is loaded
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_load128BitBlock_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load128BitBlock_buffer(uint32_t sgisfrDatOffset, mcuxCl_InputBuffer_t dataBuf, uint32_t offset);

/**
 * @brief Stores a 128-bit block of data from the SGI
 *
 * This function stores a 128-bit data block from the specified SGI
 * data register bank. Unaligned access is handled properly, as
 * well as differences in compilers and architectures.
 *
 * Data Integrity: Expunge(mcuxClSgi_Drv_getAddr(sgisfrDatOffset) + pOut + 16u)
 *
 * @param[in]  sgisfrDatOffset   Offset of the target data SGI SFR,
 *                               can be either of these values:
 *                                 #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                                 #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in]  pOut            Pointer to data buffer which data is stored to
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_store128BitBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_store128BitBlock(uint32_t sgisfrDatOffset, uint8_t *pOut);

/** Helper macro for DI balanced call to mcuxClSgi_Utils_store128BitBlock. */
#define MCUXCLSGI_UTILS_STORE128BITBLOCK_DI_BALANCED(sfrDatOffset, pOut) \
  do {  \
    MCUX_CSSL_DI_RECORD(sgiStore, ((uint32_t)mcuxClSgi_Drv_getAddr(sfrDatOffset)) + ((uint32_t)pOut) + 16u); \
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSgi_Utils_store128BitBlock)); \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClSgi_Utils_store128BitBlock(sfrDatOffset, pOut)); \
  } while(false)

/**
 * @brief Stores a 128-bit block of data from the SGI
 *
 * This function stores a 128-bit data block from the specified SGI
 * data register bank to a buffer.
 *
* SREQI_BCIPHER_1 - Use this function for data copy from SGI to user output.
 *
 * Data Integrity: Expunge(mcuxClSgi_Drv_getAddr(sgisfrDatOffset) + outBuf + offset + 16u)
 *
 * @param[in]  session           Session handle
 * @param[in]  sgisfrDatOffset   Offset of the target data SGI SFR,
 *                               can be either of these values:
 *                                 #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                                 #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in]  outBuf          Data buffer which data is stored to
 * @param[in]  offset          Offset of the data buffer to store to
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_store128BitBlock_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_store128BitBlock_buffer(mcuxClSession_Handle_t session, uint32_t sgisfrDatOffset, mcuxCl_Buffer_t outBuf, uint32_t offset);

/**
 * @brief Adds RECORD statements to balance DI offset introduced by mcuxClSgi_Utils_storeMasked128BitBlock_buffer
 *
 * @param[in]  sgisfrDatOffset    Offset of the target data SGI SFR,
 *                                can be either of these values:
 *                                  #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                  #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                  #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                  #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                                  #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in]  outBuf             Data buffer which data is stored to
 * @param[in]  offset             Offset of the data buffer to store to
 * @param[in]  pXorMask           Pointer to 128 bit xor mask
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI(uint32_t sgisfrDatOffset,
                                                                                       mcuxCl_Buffer_t outBuf,
                                                                                       uint32_t offset,
                                                                                       const uint32_t* pXorMask);

/**
 * @brief Stores a 128-bit block of data using masking from the SGI
 *
 * This function stores a 128-bit data block using masking from the specified SGI
 * data register bank to a buffer.
 *
 * Data Integrity:
 *   Use @ref mcuxClSgi_Utils_storeMasked128BitBlock_buffer_recordDI to balance the DI for this function call.
 *
 * @param[in]  session           Session handle
 * @param[in]  sgisfrDatOffset   Offset of the target data SGI SFR,
 *                               can be either of these values:
 *                                 #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN3_OFFSET
 *                                 #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param[in]  outBuf          Data buffer which data is stored to
 * @param[in]  offset          Offset of the data buffer to store to
 * @param[in]  pXorMask        Pointer to 128 bit mask
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_storeMasked128BitBlock_buffer)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storeMasked128BitBlock_buffer(
                                                               mcuxClSession_Handle_t session,
                                                               uint32_t sgisfrDatOffset,
                                                               mcuxCl_Buffer_t outBuf,
                                                               uint32_t offset,
                                                               const uint32_t *pXorMask);

/**
 * @brief Loads a 256-bit block of data to the SGI
 *
 * This function loads a 256-bit data block to the given SGI DATIN register bank.
 *
 * Data Integrity: Expunge(mcuxClSgi_Drv_getAddr(sgisfrDatOffset) + pData + 32)
 *
 * @param     sgisfrDatOffset   Offset of the target data SGI SFR,
 *                              can be either of these values:
 *                                 #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                                 #MCUXCLSGI_DRV_DATIN2_OFFSET
 * @param[in]  pData            Pointer to data buffer which is loaded (word-aligned)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_load256BitBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load256BitBlock(uint32_t sgisfrDatOffset, const uint8_t *pData);

/**
 * @brief Loads a 512-bit block of internal data to the SGI
 *
 * This function loads a 512-bit data block from internal memory
 * to the SGI DATIN register bank and subsequent KEY register banks.
 *
 * @param[in]  pData    Pointer to data buffer which is loaded (word-aligned)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_load512BitBlock, mcuxClSgi_Utils_loadInternalHashBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load512BitBlock(const uint32_t *pData);

/**
 * @brief Loads a 512-bit block of external data to the SGI.
 *
 * This function loads a 512-bit data block from external memory
 * to the SGI DATIN register bank and subsequent KEY register banks.
 *
 * Data Integrity:
 *   Use @ref mcuxClSgi_Utils_loadHashBlock_buffer_recordDI to balance the DI for this function call.
 *
 * @param[in]  session    Session handle
 * @param[in]  dataBuf    Data buffer which is loaded
 * @param[in]  offset     Offset of the input data buffer
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_load512BitBlock_buffer, mcuxClSgi_Utils_loadExternalHashBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load512BitBlock_buffer(mcuxClSession_Handle_t session, mcuxCl_InputBuffer_t dataBuf, uint32_t offset);

/**
 * @brief Loads a 1024-bit block of internal data to the SGI
 *
 * This function loads a 1024-bit data block from internal memory
 * to the SGI DATIN register bank and subsequent KEY register banks.
 *
 * @param[in]  pData    Pointer to data buffer which is loaded (word-aligned)
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_load1024BitBlock, mcuxClSgi_Utils_loadInternalHashBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load1024BitBlock(const uint32_t *pData);

/**
 * @brief Loads a 1024-bit block of external data to the SGI
 *
 * This function loads a 1024-bit data block from external memory
 * to the SGI DATIN register bank and subsequent KEY register banks.
 *
 * Data Integrity:
 *   Use @ref mcuxClSgi_Utils_loadHashBlock_buffer_recordDI to balance the DI for this function call.
 *
 * @param[in]  session    Session handle
 * @param[in]  dataBuf    Data buffer which is loaded
 * @param[in]  offset     Offset of the input data buffer
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_load1024BitBlock_buffer, mcuxClSgi_Utils_loadExternalHashBlock)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_load1024BitBlock_buffer(mcuxClSession_Handle_t session, mcuxCl_InputBuffer_t dataBuf, uint32_t offset);

/**
 * @brief Adds RECORD statements to balance DI offset introduced by mcuxClSgi_Utils_load512BitBlock_buffer
 * and mcuxClSgi_Utils_load1024BitBlock_buffer.
 *
 * Offsets the DI impact by mcuxClSgi_Utils_load1024BitBlock_buffer or mcuxClSgi_Utils_load512BitBlock_buffer.
 * Not applicable for mcuxClSgi_Utils_load128BitBlock_buffer.
 *
 * @param[in]   dataBuf         Pointer to external input buffer
 * @param[in]   offset          Byte offset for dataBuf access
 * @param[in]   blockSize       Block size of current hash algorithm (64U for _load512BitBlock_ and 128U for _load1024BitBlock_)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_loadHashBlock_buffer_recordDI)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_loadHashBlock_buffer_recordDI(mcuxCl_InputBuffer_t dataBuf, uint32_t offset, uint32_t blockSize);

/**
 * @brief Load data to FIFO
 *
 * When using SGI in auto mode for hashing, data has to be
 * loaded to FIFO. This function takes care of that.
 *
 * @param[in]  pData    Pointer to data buffer which is loaded
 * @param[in]  length   Byte-length of data
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_loadFifo)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_loadFifo(const uint32_t *pData, uint32_t length);

/**
 * @brief Store partial hash in output buffer
 *
 * Store the result of a hash operation in an output buffer during process phase.
 *
 * @param[in]  pOutput    Pointer to output buffer, where partial digest is stored word-wise.
  *                       The pointer needs to be word aligned.
 * @param[in]  length     Byte-length of result. The input length needs to be a multiple of wordsize.
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_storePartialHash)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storePartialHash(uint32_t *pOutput, uint32_t length);

/**
 * @brief Store result in output buffer
 *
 * Store the result of a hash operation in an output buffer.
 *
 * Data Integrity:
 *   Use @ref mcuxClSgi_Utils_storeHashResult_recordDI to balance the DI for this function call.
 *
 * @param[in]  session    Session handle
 * @param[in]  pOutput    Pointer to output buffer, where result is stored word-wise
 * @param[in]  length     Byte-length of result
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_storeHashResult)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storeHashResult(mcuxClSession_Handle_t session, mcuxCl_Buffer_t pOutput, uint32_t length);

/**
 * @brief Adds RECORD statements to balance DI offset introduced by mcuxClSgi_Utils_storeHashResult
 *
 * Computes the number of iterations and sum of offsets used by mcuxClSgi_Utils_storeHashResult.
 * These values are then used to offset the DI impact of mcuxClBuffer_write_word calls made by
 * mcuxClSgi_Utils_storeHashResult.
 *
 * @param[in]   pOutput       Pointer to external output buffer
 * @param[in]   length        Byte size of computed hash
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_storeHashResult_recordDI)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_storeHashResult_recordDI(mcuxCl_Buffer_t pOutput, uint32_t length);

/**
 * @brief Configure the SGI in AUTO mode with DMA handshake(s) and start the operation.
 *
 * This function configures the SGI in AUTO mode. Two DMA channels are used to tranfer
 * data to/from SGI. SGI/DMA handshake signals are enabled to coordinate the communication.
 * This function also starts the operation.
 *
 * @pre Function @ref mcuxClSgi_Drv_configureAutoMode has been called.
 *
 * @param[in]  operation              Configuration of the SGI operation to be executed
 * @param[in]  enableOutputHandshake  Enable or disable the output DMA-SGI handshake
 *
 */
#define MCUXCLSGI_UTILS_OUTPUT_HANDSHAKE_ENABLE   ((uint32_t) 1u)
#define MCUXCLSGI_UTILS_OUTPUT_HANDSHAKE_DISABLE  ((uint32_t) 0u)
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_startAutoModeWithHandshakes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_startAutoModeWithHandshakes(uint32_t operation, uint32_t enableOutputHandshake);

/**
 * @brief Stop and disable AUTO mode, disable DMA handshakes.
 *
 * This function stop and disables SGI AUTO mode, and disables all handshake related
 * settings in the SGI and the SCM for the involved DMA channel.
 *
 * @param[in]  inputChannel      DMA channel that is used to write to the SGI
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_stopAutoModeWithDmaInputHandshakes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_stopAutoModeWithDmaInputHandshakes(mcuxClSession_Channel_t inputChannel);

/**
 * @brief Stop and disable AUTO mode, disable DMA handshakes for both channels.
 *
 * This function stop and disables SGI AUTO mode, and disables all handshake related
 * settings in the SGI and the SCM for two involved DMA channels.
 *
 * @param[in]  inputChannel      DMA channel that is used to write to the SGI
 * @param[in]  outputChannel     DMA channel that is used to read from the SGI
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_stopAutoModeWithDmaHandshakes(
  mcuxClSession_Channel_t inputChannel,
  mcuxClSession_Channel_t outputChannel
);


/**
 * Internal function to request the SGI.
 *
 * @param[in]  session             Session handle
 * @param[in]  hwStatusOption      Resource status option
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_Request)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_Request(mcuxClSession_Handle_t session, mcuxClResource_HwStatus_t hwStatusOption);

/**
 * Internal function to release the SGI.
 * Will also release the HW if MCUXCL_FEATURE_SESSION_JOBS is enabled.
 *
 * @param[in]  session            Session handle
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_Uninit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_Uninit(mcuxClSession_Handle_t session);

/**
 * @brief Copy SFR-masked data to/from SGI.
 *
 * This function will enable SGI SFR-masking with the given @p sfrSeed, and disable it again after the copy.
 *
 * Data Integrity: Expunge(pSrc + pDst + length)
 *
 * @param[in] pDst     destination address
 * @param[in] pSrc     source address
 * @param[in] length   byte length of the data to be copied
 * @param[in] sfrSeed  SFR mask seed
 *
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_copySfrMasked)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_copySfrMasked(uint32_t *pDst, const uint32_t *pSrc, uint32_t length, uint32_t sfrSeed);

/**
 * @brief Load key into SGI using secure word-wise copy operation.
 *
 * @param[in]  offset      offset to key register.
 * @param[out] pKey        pointer to the key buffer.
 * @param[in]  keySize     key size.
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSgi_Utils_loadKey_secure)
static inline MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_loadKey_secure(
  uint32_t offset,
  const uint8_t *pKey,
  uint32_t keySize)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSgi_Utils_loadKey_secure);
  uint32_t *sgiKey = mcuxClSgi_Sfr_getAddr(offset);
  /* Record input data for mcuxClMemory_copy_secure_int() */
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_MODIFY_STRING_LITERALS("False positive: The constant string literal pKey is not being modified");
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, pKey);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_MODIFY_STRING_LITERALS();
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, sgiKey);
  MCUX_CSSL_DI_RECORD(mcuxClMemory_copy_secure_int, keySize);
  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy_secure_int));
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy_secure_int((uint8_t *) sgiKey, pKey, keySize));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClSgi_Utils_loadKey_secure);
}


/**
 * @brief Decrements an 16-byte value from the SGI DATIN at an offset srcSfrDatOffset and stores it at an offset dstSfrDatOffset.
 *
 * This function retrieves a 16-byte value from the SGI DATIN at an offset srcSfrDatOffset, decrements it by 1,
 * and stores the result at an dstSfrDatOffset.
 * The decremention will start at the least significant word (located at srcSfrDatOffset + 12)
 * and will end at the most significant word (located at srcSfrDatOffset).
 *
 * @param srcSfrDatOffset     Offset of the source data SGI SFR,
 *                            can be either of these values:
 *                              #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                              #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                              #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                              #MCUXCLSGI_DRV_DATOUT_OFFSET
 * @param dstSfrDatOffset     Offset of the destination data SGI SFR,
 *                            can be either of these values:
 *                              #MCUXCLSGI_DRV_DATIN0_OFFSET
 *                              #MCUXCLSGI_DRV_DATIN1_OFFSET
 *                              #MCUXCLSGI_DRV_DATIN2_OFFSET
 *                              #MCUXCLSGI_DRV_DATOUT_OFFSET
*/
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_decrement128Bit)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_decrement128Bit(uint32_t srcSfrDatOffset, uint32_t dstSfrDatOffset);

/**
 * @brief This function performs RFC3394 key unwrapping with the SGI.
 *
 * Only 128-bit and 256-bit AES key material and KWK sizes are supported.
 *
 * @post The unwrapped key material will be stored in SGI key registers that are
 * fixed by hardware, see @ref MCUXCLKEY_LOADOPTION_SLOT_SGI_KEY_UNWRAP.
 *
 * @param      session       The session handle.
 * @param      key           The key handle containing the wrapped key material
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_keyUnwrapRfc3394)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_keyUnwrapRfc3394(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key
);

/**
 * @brief This function performs RFC3394 key wrapping with the SGI.
 *
 * - Only 128-bit and 256-bit AES key material and KWK sizes are supported.
 * - The `keyMaterial` can contain either a plain key or a protected key to be wrapped.
 * - The `pSfrSeed` determines the type of key in the `keyMaterial`. For a plain key the
 *   `pSfrSeed` is NULL, and for a protected key the `pSfrSeed` holds the seed for SFR masking.
 * - The protected key is loaded to SGI in blocks of `RFC3394_BLOCK_SIZE` using a special type
 *   of SFR masking, that is tightly coupled to how the keys were produced in the
 *   `mcuxClAes_keyUnwrapRfc3394_swDriven` function. And the `pSfrSeed` is re-initialized
 *   for each block before it is loaded to SGI, for them to be unmasked correctly.
 *
 * @post The wrapped key material will be stored in the container of the @p key.
 *
 * @param      session       The session handle.
 * @param      key           The key handle.
 * @param[in]  keyMaterial   A pointer to the key material to be wrapped.
 * @param[in]  pSfrSeed      Seed for the SFR-masked key.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClSgi_Utils_keyWrapRfc3394)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClSgi_Utils_keyWrapRfc3394(
  mcuxClSession_Handle_t session,
  mcuxClKey_Handle_t key,
  const uint8_t* pKeyMaterial,
  const uint32_t* pSfrSeed
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLSGI_UTILS_H_ */
