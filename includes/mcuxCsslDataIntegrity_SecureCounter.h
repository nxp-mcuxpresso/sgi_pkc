/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * \file  mcuxCsslDataIntegrity_SecureCounter.h
 * \brief Implementation that enables the CSSL data integrity mechanism, based on secure counter.
 */

#ifndef MCUXCSSLDATAINTEGRITY_SECURECOUNTER_H_
#define MCUXCSSLDATAINTEGRITY_SECURECOUNTER_H_

#include <mcuxCsslAnalysis.h>
#include <mcuxCsslFlowProtection.h>

#if (1 == MCUX_CSSL_SC_USE_SW_LOCAL) && (0 == MCUX_CSSL_FP_USE_SECURE_COUNTER)
  #error "Local SW SC is not supported for DI when FP does not use this local SW SC, as SC_ALLOC would be missing."
#endif

/**
 * \addtogroup mcuxCsslIMPL MCUX CSSL -- Implementations
 *
 * \defgroup mcuxCsslDataIntegrity_SC Data Integrity: Secure Counter
 * \brief Enable the CSSL data integrity mechanism, based on secure counter.
 * \ingroup mcuxCsslIMPL
 */


/**
 * \defgroup diScCore Data integrity core functionality
 * \brief Data integrity handling core functionality, based on secure counter.
 * \ingroup mcuxCsslDataIntegrity_SC
 */


/****************************************************************************/
/* Constants                                                                */
/****************************************************************************/

/**
 * \def MCUX_CSSL_DI_CHECK_PASSED_IMPL
 * \brief Positive comparison result value.
 * \ingroup diScCore
 */
#define MCUX_CSSL_DI_CHECK_PASSED_IMPL (MCUX_CSSL_SC_CHECK_PASSED)

/**
 * \def MCUX_CSSL_DI_CHECK_FAILED_IMPL
 * \brief Negative comparison result value.
 * \ingroup diScCore
 */
#define MCUX_CSSL_DI_CHECK_FAILED_IMPL (MCUX_CSSL_SC_CHECK_FAILED)


/****************************************************************************/
/* Macros that depend on the implementation of the secure counter mechanism */
/****************************************************************************/

#if (1 == MCUX_CSSL_SC_USE_HW_SCM)
/**
 * \def MCUX_CSSL_DI_BACKUP_SC
 * \brief Backs up the secure counter reference value from the corresponding HW SFR,
          then overwrites the reference value with the current secure counter value.
 * \ingroup diScCore
 *
 * @param backupValue Fresh variable name to store the reference SC value.
 */
#define MCUX_CSSL_DI_BACKUP_SC(backupValue) \
  uint32_t backupValue = MCUX_CSSL_SC_REF_VALUE_IMPL(); \
  MCUX_CSSL_SC_REF_VALUE_IMPL() = MCUX_CSSL_SC_VALUE()

/**
 * \def MCUX_CSSL_DI_RESTORE_SC_REF
 * \brief Restores the secure counter reference value to the corresponding HW SFR.
 * \ingroup diScCore
 *
 * @param reference Secure counter reference value that will be written to the HW SFR.
 */
#define MCUX_CSSL_DI_RESTORE_SC_REF(reference) \
  MCUX_CSSL_SC_REF_VALUE_IMPL() = (reference)

#else
/**
 * \def MCUX_CSSL_DI_BACKUP_SC
 * \brief Backs up the current secure counter value.
 * \ingroup diScCore
 *
 * @param backupValue Fresh variable name to store the current SC value.
 */
#define MCUX_CSSL_DI_BACKUP_SC(backupValue) \
  uint32_t backupValue = MCUX_CSSL_SC_VALUE()

/**
 * \def MCUX_CSSL_DI_RESTORE_SC_REF
 * \brief Restores the data integrity reference value to the corresponding HW SFR.
 * \ingroup diScCore
 *
 * @param reference Data integrity reference value that will be written to the HW SFR (ignored).
 */
#define MCUX_CSSL_DI_RESTORE_SC_REF(reference)

#endif

/****************************************************************************/
/* Initialization                                                           */
/****************************************************************************/

#if (1 == MCUX_CSSL_FP_USE_SECURE_COUNTER)
/**
 * \def MCUX_CSSL_DI_INIT_IMPL
 * \brief Initialize the backup of the data integrity value to zero, when
 *        the Flow Protection mechanism already uses the secure counter.
 *        Note that in case the secure counter back-end requires allocation, it
 *        is expected that this will be handled by the Flow Protection mechanism
 *        before the initialization of the Data Integrity.
 * \ingroup diScCore
 *
 * @param backupValue Fresh variable name to store the current DI value.
 */
#define MCUX_CSSL_DI_INIT_IMPL(backupValue) \
  uint32_t backupValue = 0u
#else
/**
 * \def MCUX_CSSL_DI_INIT_IMPL
 * \brief Backup of the current data integrity value, that will be checked later
 *        on with MCUX_CSSL_SC_CHECK.
 *        Note that in case the secure counter back-end requires allocation, it
 *        is expected that this will be handled by the Flow Protection mechanism
 *        before the initialization of the Data Integrity.
 * \ingroup diScCore
 *
 * @param backupValue Fresh variable name to store the current DI value.
 */
#define MCUX_CSSL_DI_INIT_IMPL(backupValue) \
  MCUX_CSSL_DI_BACKUP_SC(backupValue)
#endif


/****************************************************************************/
/* Check                                                                    */
/****************************************************************************/

/**
 * \def MCUX_CSSL_DI_CHECK_IMPL
 * \brief Comparison operation implementation for the data integrity.
 * \ingroup diScCore
 *
 * \param reference Reference initial value to compare the data integrity value against.
 * \return          Either #MCUX_CSSL_DI_CHECK_PASSED, if the value matches, or
 *                  #MCUX_CSSL_DI_CHECK_FAILED if the value is different.
 */
#define MCUX_CSSL_DI_CHECK_IMPL(reference) \
  MCUX_CSSL_SC_CHECK(reference)

#if (1 == MCUX_CSSL_FP_USE_SECURE_COUNTER)
/**
 * \def MCUX_CSSL_DI_CHECK_EXIT_IMPL
 * \brief Comparison operation implementation for the data integrity, when the
 *        Flow Protection mechanism already uses the secure counter.
 *        It has no impact on the normal execution of the calling function.
 * \ingroup diScCore
 *
 * \param id        Identifier of the function from which we will exit (ignored).
 * \param reference Reference value to compare the data integrity value against (ignored).
 * \param fail      Result that should be returned if the data integrity check failed (ignored).
 */
#define MCUX_CSSL_DI_CHECK_EXIT_IMPL(id, reference, fail) \
  (void)(reference)
#else
/**
 * \def MCUX_CSSL_DI_CHECK_EXIT_IMPL
 * \brief Comparison operation implementation for the data integrity.
 *        It compares the data integrity value to the reference initial value,
 *        and exits with the given fault status code if the comparison fails.
 *        The reference value shall be the initial value that was backed up
 *        with MCUX_CSSL_DI_INIT.
 *        If the comparison succeeds, the reference value is restored to
 *        the HW SFR, and normal execution will continue.
 * \ingroup diScCore
 *
 * \param id        Identifier of the function from which we will exit.
 * \param reference Reference initial data integrity value that will be restored to the HW SFR.
 * \param fail      Result that should be returned if the data integrity check failed.
 */
#define MCUX_CSSL_DI_CHECK_EXIT_IMPL(id, reference, fail) \
  if (MCUX_CSSL_DI_CHECK_PASSED != MCUX_CSSL_DI_CHECK(reference)) \
  { \
    MCUX_CSSL_FP_FUNCTION_EXIT(id, fail); \
  } \
  MCUX_CSSL_DI_RESTORE_SC_REF(reference);
#endif


/****************************************************************************/
/* Updates                                                                  */
/****************************************************************************/

/**
 * \defgroup diScUpdate Data integrity record
 * \brief Support for recording a value in the data integrity register, based on secure counter.
 * \ingroup mcuxCsslDataIntegrity_SC
 */

/**
 * \def MCUX_CSSL_DI_RECORD_IMPL
 * \brief Implementation: Record the value for data integrity checking.
 * \ingroup diScUpdate
 *
 * \param identifier Identifier for the value that will be recorded.
 * \param value      Value which needs to be recorded for the given identifier.
 */
#define MCUX_CSSL_DI_RECORD_IMPL(identifier, value) \
  MCUX_CSSL_ANALYSIS_START_PATTERN_DI_CAST() \
  MCUX_CSSL_SC_ADD(value) \
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_DI_CAST()

/**
 * \def MCUX_CSSL_DI_EXPUNGE_IMPL
 * \brief Implementation: Expunge the record for value.
 * \ingroup diScUpdate
 *
 * \param identifier Identifier for the value that will be expunged.
 * \param value      Expected value that was recorded for the given identifier.
 */
#define MCUX_CSSL_DI_EXPUNGE_IMPL(identifier, value) \
  MCUX_CSSL_ANALYSIS_START_PATTERN_DI_CAST() \
  MCUX_CSSL_SC_SUB(value) \
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_DI_CAST()

#endif /* MCUXCSSLDATAINTEGRITY_SECURECOUNTER_H_ */
