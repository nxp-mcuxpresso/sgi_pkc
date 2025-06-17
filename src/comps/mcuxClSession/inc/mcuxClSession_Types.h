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

/**
 * @file  mcuxClSession_Types.h
 * @brief Type definitions for the mcuxClSession component
 */

#ifndef MCUXCLSESSION_TYPES_H_
#define MCUXCLSESSION_TYPES_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>

#include <mcuxClRandom_Types.h>
#include <mcuxClResource_Types.h>

/**********************************************
 * CONSTANTS
 **********************************************/
/**
 * @defgroup mcuxClSession_Constants mcuxClSession_Constants
 * @brief Defines all constants of @ref mcuxClSession
 * @ingroup mcuxClSession
 * @{
 */

#define MCUXCLSESSION_STATUS_OK                          ((mcuxClSession_Status_t) 0x0EEE2E03u)  ///< Session operation successful
#define MCUXCLSESSION_STATUS_ERROR                       ((mcuxClSession_Status_t) 0x0EEE5330u)  ///< Error occurred during Session operation
#define MCUXCLSESSION_STATUS_ERROR_MEMORY_ALLOCATION     ((mcuxClSession_Status_t) 0x0EEE534Fu)  ///< Error occurred during Session operation (Not enough memory)
#define MCUXCLSESSION_STATUS_FAULT_ATTACK                ((mcuxClSession_Status_t) 0x0EEEF0F0u)  ///< Fault attack

#define MCUXCLSESSION_DMACHANNEL_INVALID  ((mcuxClSession_Channel_t) 0xFFFFu)    ///< dma channel is not specified



/**
 * @}
 */
/* mcuxClSession_Constants */

/**********************************************
 * TYPEDEFS
 **********************************************/
/**
 * @defgroup mcuxClSession_Types mcuxClSession_Types
 * @brief Defines all types of @ref mcuxClSession
 * @ingroup mcuxClSession
 * @{
 */

/**
 * @brief Type for mcuxClSession status codes
 */
typedef uint32_t mcuxClSession_Status_t;

/**
 * @brief Deprecated type for mcuxClSession protected status codes
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_Status_Protected_t;

/**
 * @brief Type for mcuxClSession workareas flags
 */
typedef struct mcuxClSession_WorkArea
{
  uint32_t * buffer;            ///< Pointer to the starting address of the workarea buffer
  uint32_t size;                ///< Size of the workarea buffer in words (uint32_t)
  uint32_t used;                ///< Used portion of the workarea buffer in words (uint32_t)
  uint32_t dirty;               ///< Maximum used portion of the workarea buffer in words (uint32_t)
} mcuxClSession_WorkArea_t;

/**
 * @brief Type for Session security options
 */
typedef uint32_t mcuxClSession_SecurityOptions_t;

/**
 * @brief Type for mcuxClSession Descriptor
 */
struct mcuxClSession_Descriptor;  /* forward declaration */
typedef struct mcuxClSession_Descriptor mcuxClSession_Descriptor_t;

/**
 * @brief Type for mcuxClSession Handle
 */
typedef mcuxClSession_Descriptor_t * const mcuxClSession_Handle_t;

/**
 * @brief Session channel type
 *
 * This type identifies DMA channel to be used during non-blocking operations.
 */
typedef uint16_t mcuxClSession_Channel_t;

/**
 * @brief Session channels type
 *
 * This type identifies DMA channels to be used during non-blocking operations.
 */
typedef struct
{
  mcuxClSession_Channel_t input;
  mcuxClSession_Channel_t output;
} mcuxClSession_Channels_t;

/**
 * @brief Session callback function pointer type
 *
 * This type is used to pass callback functions to be triggered by the Session.
 */
typedef void (*mcuxClSession_Callback_t)(uint32_t status, void * data);

/**
 * @brief HW interrupt handler function pointer type
 *
 * This type is used to pass HW interrupt handler (callback function)
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClSession_HwInterruptHandler_t,
  typedef MCUX_CSSL_FP_PROTECTED_TYPE(void) (*mcuxClSession_HwInterruptHandler_t)(mcuxClSession_Handle_t session)
);

/**
 * @brief Table recording HW preempted from this session
 */
typedef struct mcuxClSession_HwTable mcuxClSession_HwTable_t;

/**
 * @brief Type for mcuxClSession non-blocking job context
 */
typedef struct
{
  mcuxClSession_Channels_t dmaChannels;
  mcuxClSession_Callback_t pUserCallback;
  void *pUserData;
  mcuxClSession_HwInterruptHandler_t pCallBackDMA;
  uint32_t                          protectionToken_pCallBackDMA;
  mcuxClSession_HwInterruptHandler_t pCallBackCopro;
  uint32_t                          protectionToken_pCallBackCopro;
  void *pClWorkarea; /* Used for non blocking flow to handover cl data to the interrupt */
} mcuxClSession_JobContext_t;

/**
 * @brief Type for mcuxClSession API calls
 */
typedef struct mcuxClSession_apiCall mcuxClSession_apiCall_t;

/**
 * @brief Structure for mcuxClSession Descriptor
 */
struct mcuxClSession_Descriptor
{
  mcuxClSession_WorkArea_t cpuWa;    ///< Workarea for the CPU
  mcuxClSession_WorkArea_t pkcWa;    ///< Workarea for the PKC
  mcuxClRandom_Config_t randomCfg;   ///< Configuration of the Rng (contexts and mode)
  mcuxClResource_Context_t * pResourceCtx;  ///< Pointer to global resource context
  mcuxClSession_JobContext_t jobContext;    ///< Context of non-blocking job
  mcuxClSession_apiCall_t * apiCall;  ///< Context for API calls
};


/**
 * @}
 */ /* mcuxClSession_Types */

#endif /* MCUXCLSESSION_TYPES_H_ */
