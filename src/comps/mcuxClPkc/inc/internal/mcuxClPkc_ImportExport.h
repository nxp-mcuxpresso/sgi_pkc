/*--------------------------------------------------------------------------*/
/* Copyright 2021-2024 NXP                                                  */
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

/**
 * @file  mcuxClPkc_ImportExport.h
 * @brief Declaration of PKC internal import/export functions of mcuxClPkc component
 */


#ifndef MCUXCLPKC_IMPORTEXPORT_H_
#define MCUXCLPKC_IMPORTEXPORT_H_


#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>

#include <mcuxClSession.h>
#include <mcuxClMemory.h>

#include <internal/mcuxClPkc_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**********************************************************/
/* Import/export function declaration                     */
/**********************************************************/

/**
 * @brief Function to switch the endianness of the data in a buffer
 * 
 * This function switches the endianness of a data buffer of a specified length.
 * 
 * @param[in/out]  ptr     pointer to data buffer of which endianness is switched
 * @param          length  length of data buffer pointed to by ptr
 * 
 * @pre
 *  - @p ptr pointer shall be CPU word aligned.
 *  - if @p length is not a multiple of CPU wordsize, this function will:
 *     - cause unaligned word access and sometimes byte access, on platform supporting unaligned access;
 *     - switch endianness byte-wisely, on platform not supporting unaligned access.
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPkc_SwitchEndianness)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_SwitchEndianness(uint32_t *ptr, uint32_t length);

/** Helper macro to call #mcuxClPkc_SwitchEndianness with flow protection. */
#define MCUXCLPKC_FP_SWITCHENDIANNESS(ptr, length) \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_SwitchEndianness(ptr, length))

/**
 * @brief Function to import an operand, which is provided in big-endian order
 * 
 * This function imports an integer stored as a big-endian octet string with specified length
 * and stores it as an integer in PKC workarea according PKC specification.
 * 
 * @param[out]  iTarget                 index of PKC operand, where the imported integer will be stored
 * @param[in]   pSource                 address of the octet string to be imported
 * @param       length                  length of the octet string to be imported
 * @param       targetBufferLength      length of the buffer iTarget
 * 
 * @pre
 *  - @p iTarget is the index of the PKC operand, size = targetBufferLength.
 *    The bytes on top of this operand will be cleared to zero if length < targetBufferLength.
 *    The offset (UPTRT[iTarget]) shall be exactly a multiple of MCUXCLPKC_WORDSIZE.
 *  - @p length shall be equal to or smaller than targetBufferLength.
 *  - @p targetBufferLength shall be equal to the buffer size of iTarget and a multiple of MCUXCLPKC_WORDSIZE.
 * 
 * @post
 *  - Data Integrity: Expunge(iTarget + pSource + length + targetBufferLength)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPkc_ImportBigEndianToPkc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_ImportBigEndianToPkc(uint8_t iTarget, const uint8_t * pSource, uint32_t length, uint32_t targetBufferLength);

/** Helper macro to call #mcuxClPkc_ImportBigEndianToPkc with flow protection. */
#define MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_DI_BALANCED(iTarget, pSource, length, buffLength) \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ImportBigEndianToPkc /* not used*/, iTarget); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ImportBigEndianToPkc /* not used*/, pSource); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ImportBigEndianToPkc /* not used*/, length); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ImportBigEndianToPkc /* not used*/, buffLength); \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_ImportBigEndianToPkc(iTarget, pSource, length, buffLength))

/** Helper macros to use the correct buffer implementation */
#define MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFEROFFSET  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportBigEndianToPkc)
#define MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFEROFFSET_DI_BALANCED(functionID, iTarget, pBufSource, offset, length, buffLength) \
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_DI_BALANCED(iTarget, & ((const uint8_t *) (pBufSource))[offset], length, buffLength)
#define MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFER  MCUXCLPKC_FP_CALLED_IMPORTBIGENDIANTOPKC_BUFFEROFFSET
#define MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(functionID, iTarget, pBufSource, length, buffLength) \
    MCUXCLPKC_FP_IMPORTBIGENDIANTOPKC_BUFFEROFFSET_DI_BALANCED(functionID, iTarget, pBufSource, 0u, length, buffLength)


/**
* @brief Function to import an operand, which is provided in little-endian order

 * This function imports an integer stored as a little-endian octet string with specified length
 * and stores it as an integer in PKC workarea according PKC specification.
 * 
 * @param[out]  iTarget                 index of PKC operand, where the imported integer will be stored
 * @param[in]   pSource                 address of the octet string to be imported
 * @param       length                  length of the octet string to be imported
 * @param       targetBufferLength      length of the buffer iTarget
 * 
 * @pre
 *  - @p iTarget is the index of the PKC operand, size = targetBufferLength.
 *    The bytes on top of this operand will be cleared to zero if length < targetBufferLength.
 *    The offset (UPTRT[iTarget]) shall be exactly a multiple of MCUXCLPKC_WORDSIZE.
 *  - @p length shall be equal to or smaller than targetBufferLength.
 *  - @p targetBufferLength shall be equal to the buffer size of iTarget and a multiple of MCUXCLPKC_WORDSIZE.
 * 
 * @post
 *  - Data Integrity: Expunge(iTarget + pSource + length + targetBufferLength)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPkc_ImportLittleEndianToPkc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_ImportLittleEndianToPkc(uint8_t iTarget, const uint8_t * pSource, uint32_t length, uint32_t targetBufferLength);

/** Helper macro to call #mcuxClPkc_ImportLittleEndianToPkc with flow protection. */
#define MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(iTarget, pSource, length, buffLength) \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ImportLittleEndianToPkc /* not used*/, iTarget); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ImportLittleEndianToPkc /* not used*/, pSource); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ImportLittleEndianToPkc /* not used*/, length); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ImportLittleEndianToPkc /* not used*/, buffLength); \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_ImportLittleEndianToPkc(iTarget, pSource, length, buffLength))

/** Helper macros to use the correct buffer implementation */
#define MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFEROFFSET  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc)
#define MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_BUFFEROFFSET_DI_BALANCED(functionID, iTarget, pBufSource, offset, length, buffLength) \
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_DI_BALANCED(iTarget, & ((const uint8_t *) (pBufSource))[offset], length, buffLength)
#define MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFER  MCUXCLPKC_FP_CALLED_IMPORTLITTLEENDIANTOPKC_BUFFEROFFSET
#define MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_BUFFER_DI_BALANCED(functionID, iTarget, pBufSource, length, buffLength) \
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC_BUFFEROFFSET_DI_BALANCED(functionID, iTarget, pBufSource, 0u, length, buffLength)


/**
 * @brief Function to export an operand to a big-endian integer
 * 
 * This function exports a PKC integer in PKC workarea and stores it as a big-endian octet string
 * in a buffer specified by the given address and length.
 * 
 * @param[out]  pTarget  address of operand, where the exported integer will be stored
 * @param[in]   iSource  index of PKC operand to be exported
 * @param       length   length of the octet string to be exported
 * 
 * @pre
 *  - @p iSource is the index of the PKC operand, size = PKC PS1LEN.
 *    The offset (UPTRT[iSource]) shall be exactly a multiple of MCUXCLPKC_WORDSIZE.
 *  - @p length shall be equal to or smaller than PKC PS1LEN.
 * 
 * @post
 *  - Data Integrity: Expunge(pTarget + iSource + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPkc_ExportBigEndianFromPkc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_ExportBigEndianFromPkc(uint8_t * pTarget, uint8_t iSource, uint32_t length);

/** Helper macro to call #mcuxClPkc_ExportBigEndianFromPkc with flow protection. */
#define MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_DI_BALANCED(pTarget, iSource, length) \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ExportBigEndianFromPkc /* not used*/, pTarget); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ExportBigEndianFromPkc /* not used*/, iSource); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ExportBigEndianFromPkc /* not used*/, length); \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_ExportBigEndianFromPkc(pTarget, iSource, length))

/** Helper macros to use the correct buffer implementation */
#define MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFEROFFSET  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportBigEndianFromPkc)
#define MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFEROFFSET_DI_BALANCED(functionID, pBufTarget, iSource, offset, length) \
    MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_DI_BALANCED(& ((uint8_t *) (pBufTarget))[offset], iSource, length)
#define MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFER  MCUXCLPKC_FP_CALLED_EXPORTBIGENDIANFROMPKC_BUFFEROFFSET
#define MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFER_DI_BALANCED(functionID, pBufTarget, iSource, length) \
    MCUXCLPKC_FP_EXPORTBIGENDIANFROMPKC_BUFFEROFFSET_DI_BALANCED(functionID, pBufTarget, iSource, 0u, length)


/**
 * @brief Function to export an operand to a little-endian integer
 * 
 * This function exports a PKC integer in PKC workarea and stores it as a little-endian octet string
 * in a buffer specified by the given address and length.
 *
 * @param[out]  pTarget  address of operand, where the exported integer will be stored
 * @param[in]   iSource  index of PKC operand to be exported
 * @param       length   length of the octet string to be exported
 * 
 * @pre
 *   - @p iSource is the index of the PKC operand, size = PKC PS1LEN.
 *     The offset (UPTRT[iSource]) shall be exactly a multiple of MCUXCLPKC_WORDSIZE.
 *   - @p length shall be equal to or smaller than PKC PS1LEN.
 * 
 * @post
 *  - Data Integrity: Expunge(pTarget + iSource + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPkc_ExportLittleEndianFromPkc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_ExportLittleEndianFromPkc(uint8_t * pTarget, uint8_t iSource, uint32_t length);

/** Helper macro to call #mcuxClPkc_ExportLittleEndianFromPkc with flow protection. */
#define MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pTarget, iSource, length) \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ExportLittleEndianFromPkc /* not used*/, pTarget); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ExportLittleEndianFromPkc /* not used*/, iSource); \
    MCUX_CSSL_DI_RECORD(mcuxClPkc_ExportLittleEndianFromPkc /* not used*/, length); \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_ExportLittleEndianFromPkc(pTarget, iSource, length))

/** Helper macros to use the correct buffer implementation */
#define MCUXCLPKC_FP_CALLED_EXPORTLITTLEENDIANFROMPKC_BUFFEROFFSET  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ExportLittleEndianFromPkc)
#define MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_BUFFEROFFSET_DI_BALANCED(functionID, pBufTarget, iSource, offset, length) \
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_DI_BALANCED(& ((uint8_t *) (pBufTarget))[offset], iSource, length)
#define MCUXCLPKC_FP_CALLED_EXPORTLITTLEENDIANFROMPKC_BUFFER  MCUXCLPKC_FP_CALLED_EXPORTLITTLEENDIANFROMPKC_BUFFEROFFSET
#define MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_BUFFER_DI_BALANCED(functionID, pBufTarget, iSource, length) \
    MCUXCLPKC_FP_EXPORTLITTLEENDIANFROMPKC_BUFFEROFFSET_DI_BALANCED(functionID, pBufTarget, iSource, 0u, length)


/**
 * @brief Function to securely import an operand, which is provided in big-endian order
 * 
 * This function imports an integer stored as a big-endian octet string with specified length
 * and stores it as an integer in PKC workarea according PKC specification, in a secure manner.
 * 
 * @param[out]  iTarget                 index of PKC operand, where the imported integer will be stored
 * @param[in]   pSource                 address of the octet string to be imported
 * @param       length                  length of the octet string to be imported
 * @param       targetBufferLength      length of the buffer iTarget
 * 
 * @pre
 *  - @p iTarget is the index of Target (PKC operand), size = targetBufferLength, where the imported integer
 *    will be stored. The bytes on top of this operand will be cleared to zero if length < targetBufferLength.
 *    The offset (UPTRT[iTarget]) shall be exactly a multiple of MCUXCLPKC_WORDSIZE.
 *  - @p length shall be equal to or smaller than targetBufferLength.
 *  - @p targetBufferLength shall be equal to the buffer size of iTarget and a multiple of MCUXCLPKC_WORDSIZE.
 *
 * @post
 *  - Data Integrity: Expunge(iTarget + pSource + length + targetBufferLength)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPkc_SecureImportBigEndianToPkc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_SecureImportBigEndianToPkc(uint8_t iTarget, const uint8_t * pSource, uint32_t length, uint32_t targetBufferLength);

/** Helper macro to call #mcuxClPkc_SecureImportBigEndianToPkc with flow protection. */
#define MCUXCLPKC_FP_SECUREIMPORTBIGENDIANTOPKC_DI_BALANCED(pSession, iTarget, pSource, length, buffLength) \
    do{ \
        (void)pSession; /* not used*/ \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureImportBigEndianToPkc /* not used*/, iTarget); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureImportBigEndianToPkc /* not used*/, pSource); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureImportBigEndianToPkc /* not used*/, length); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureImportBigEndianToPkc /* not used*/, buffLength); \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_SecureImportBigEndianToPkc(iTarget, pSource, length, buffLength)); \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION() \
    } while(false)                                                         \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()


/** Helper macros to use the correct buffer implementation */
#define MCUXCLPKC_FP_CALLED_SECUREIMPORTBIGENDIANTOPKC_BUFFER  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SecureImportBigEndianToPkc)
#define MCUXCLPKC_FP_SECUREIMPORTBIGENDIANTOPKC_BUFFER_DI_BALANCED(functionID, status, pSession, iTarget, pBufSource, length, buffLength) \
    MCUXCLPKC_FP_SECUREIMPORTBIGENDIANTOPKC_DI_BALANCED(pSession, iTarget, pBufSource, length, buffLength); \
    mcuxClPkc_Status_t status = MCUXCLPKC_STATUS_OK


/**
 * @brief Function to securely import an operand, which is provided in little-endian order
 * 
 * This function imports an integer stored as a little-endian octet string with specified length
 * and stores it as an integer in PKC workarea according PKC specification, in a secure manner.
 * 
 * @param[out]  iTarget                 index of PKC operand, where the imported integer will be stored
 * @param[in]   pSource                 address of the octet string to be imported
 * @param       length                  length of the octet string to be imported
 * @param       targetBufferLength      length of the buffer iTarget
 * 
 * @pre
 *  - @p iTarget is the index of the PKC operand, size = targetBufferLength, the bytes on top of this operand
 *    will be cleared to zero if length < targetBufferLength.
 *    The offset (UPTRT[iTarget]) shall be exactly a multiple of MCUXCLPKC_WORDSIZE.
 *  - @p length shall be equal to or smaller than targetBufferLength.
 *  - @p targetBufferLength shall be equal to the buffer size of iTarget and a multiple of MCUXCLPKC_WORDSIZE.
 * 
 * @post
 *  -  Data Integrity: Expunge(iTarget + pSource + length + targetBufferLength)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPkc_SecureImportLittleEndianToPkc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_SecureImportLittleEndianToPkc(uint8_t iTarget, const uint8_t * pSource, uint32_t length, uint32_t targetBufferLength);

/** Helper macro to call #mcuxClPkc_SecureImportLittleEndianToPkc with flow protection. */
#define MCUXCLPKC_FP_SECUREIMPORTLITTLEENDIANTOPKC_DI_BALANCED(iTarget, pSource, length, buffLength) \
    do{ \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureImportLittleEndianToPkc /* not used*/, iTarget); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureImportLittleEndianToPkc /* not used*/, pSource); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureImportLittleEndianToPkc /* not used*/, length); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureImportLittleEndianToPkc /* not used*/, buffLength); \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_SecureImportLittleEndianToPkc(iTarget, pSource, length, buffLength)); \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION() \
    } while(false)                                                         \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()

/** Helper macros to use the correct buffer implementation */
#define MCUXCLPKC_FP_CALLED_SECUREIMPORTLITTLEENDIANTOPKC_BUFFER  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SecureImportLittleEndianToPkc)
#define MCUXCLPKC_FP_SECUREIMPORTLITTLEENDIANTOPKC_BUFFER_DI_BALANCED(functionID, status, iTarget, pBufSource, length, buffLength) \
    MCUXCLPKC_FP_SECUREIMPORTLITTLEENDIANTOPKC_DI_BALANCED(iTarget, pBufSource, length, buffLength); \
    mcuxClPkc_Status_t status = MCUXCLPKC_STATUS_OK


/**
 * @brief Function to securely export an operand to a big-endian integer
 * 
 * This function exports a PKC integer in PKC workarea and stores it as a big-endian octet string
 * in a buffer specified by the given address and length, in a secure manner.
 * 
 * @param[out]  pTarget        address of operand, where the exported integer will be stored
 * @param[in]   iSource        index of PKC operands Source
 * @param       length         length of the octet string to be exported
 * 
 * @pre
 *  - @p iSource is the index of Source (PKC operand) to be exported, size = PKC PS1LEN.
 *    The offset (UPTRT[iSource]) shall be exactly a multiple of MCUXCLPKC_WORDSIZE.
 *  - @p length shall be equal to or smaller than PKC PS1LEN.
 * 
 * @post
 *  - Data Integrity: Expunge(pTarget + iSource + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPkc_SecureExportBigEndianFromPkc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_SecureExportBigEndianFromPkc(uint8_t * pTarget, uint8_t iSource, uint32_t length);

/** Helper macro to call #mcuxClPkc_SecureExportBigEndianFromPkc with flow protection. */
#define MCUXCLPKC_FP_SECUREEXPORTBIGENDIANFROMPKC_DI_BALANCED(pSession, pTarget, iSource, length) \
  do{ \
        (void)pSession; /* not used*/ \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureExportBigEndianFromPkc /* not used*/, pTarget); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureExportBigEndianFromPkc /* not used*/, iSource); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureExportBigEndianFromPkc /* not used*/, length); \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_SecureExportBigEndianFromPkc(pTarget, iSource, length)); \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION() \
    } while(false)                                                         \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()

/** Helper macros to use the correct buffer implementation */
#define MCUXCLPKC_FP_CALLED_SECUREEXPORTBIGENDIANFROMPKC_BUFFEROFFSET  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SecureExportBigEndianFromPkc)
#define MCUXCLPKC_FP_SECUREEXPORTBIGENDIANFROMPKC_BUFFEROFFSET_DI_BALANCED(functionID, status, pSession, pBufTarget, iSource, offset, length) \
    MCUXCLPKC_FP_SECUREEXPORTBIGENDIANFROMPKC_DI_BALANCED(pSession, & ((uint8_t *) (pBufTarget))[offset], iSource, length); \
    mcuxClPkc_Status_t status = MCUXCLPKC_STATUS_OK
#define MCUXCLPKC_FP_CALLED_SECUREEXPORTBIGENDIANFROMPKC_BUFFER  MCUXCLPKC_FP_CALLED_SECUREEXPORTBIGENDIANFROMPKC_BUFFEROFFSET
#define MCUXCLPKC_FP_SECUREEXPORTBIGENDIANFROMPKC_BUFFER_DI_BALANCED(functionID, status, pSession, pBufTarget, iSource, length) \
    MCUXCLPKC_FP_SECUREEXPORTBIGENDIANFROMPKC_BUFFEROFFSET_DI_BALANCED(functionID, status, pSession, pBufTarget, iSource, 0u, length)


/**
 * @brief Function to securely export an operand to a little-endian integer
 * 
 * This function exports a PKC integer in PKC workarea and stores it as a little-endian octet string
 * in a buffer specified by the given address and length, in a secure manner.
 * 
 * @param[out]  pTarget  address of operand, where the exported integer will be stored
 * @param[in]   iSource  index of PKC operand to be exported
 * @param       length   length of the octet string to be exported
 * 
 * @pre
 *  - @p iSource is the index of Source (PKC operand) to be exported, size = PKC PS1LEN.
 *    The offset (UPTRT[iSource]) shall be exactly a multiple of MCUXCLPKC_WORDSIZE.
 *   - @p length shall be equal to or smaller than PKC PS1LEN.
 * 
 * @post
 *  - Data Integrity: Expunge(pTarget + iSource + length)
 *
 * @return void
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClPkc_SecureExportLittleEndianFromPkc)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClPkc_SecureExportLittleEndianFromPkc(uint8_t * pTarget, uint8_t iSource, uint32_t length);

/** Helper macro to call #mcuxClPkc_SecureExportLittleEndianFromPkc with flow protection. */
#define MCUXCLPKC_FP_SECUREEXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pTarget, iSource, length) \
    do{ \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureExportLittleEndianFromPkc /* not used*/, pTarget); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureExportLittleEndianFromPkc /* not used*/, iSource); \
        MCUX_CSSL_DI_RECORD(mcuxClPkc_SecureExportLittleEndianFromPkc /* not used*/, length); \
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClPkc_SecureExportLittleEndianFromPkc(pTarget, iSource, length)); \
MCUX_CSSL_ANALYSIS_START_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION() \
    } while(false)                                                         \
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_BOOLEAN_TYPE_FOR_CONDITIONAL_EXPRESSION()

/** Helper macros to use the correct buffer implementation */
#define MCUXCLPKC_FP_CALLED_SECUREEXPORTLITTLEENDIANFROMPKC_BUFFER  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SecureExportLittleEndianFromPkc)
#define MCUXCLPKC_FP_SECUREEXPORTLITTLEENDIANFROMPKC_BUFFER_DI_BALANCED(functionID, status, pBufTarget, iSource, length) \
    MCUXCLPKC_FP_SECUREEXPORTLITTLEENDIANFROMPKC_DI_BALANCED(pBufTarget, iSource, length); \
    mcuxClPkc_Status_t status = MCUXCLPKC_STATUS_OK


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLPKC_IMPORTEXPORT_H_ */
