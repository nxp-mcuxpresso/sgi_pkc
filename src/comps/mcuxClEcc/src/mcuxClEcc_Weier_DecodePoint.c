/*--------------------------------------------------------------------------*/
/* Copyright 2022, 2024-2025 NXP                                            */
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
 * @file  mcuxClEcc_Weier_DecodePoint.c
 * @brief ECC Weierstrass point decoding function
 */


#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal.h>

#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal_FP.h>

#include <internal/mcuxClSession_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_WeierECC_DecodePoint)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_WeierECC_DecodePoint(
    mcuxClSession_Handle_t pSession,
    mcuxCl_InputBuffer_t pEncodedPoint,
    mcuxCl_Buffer_t pDecodedPoint,
    mcuxClEcc_WeierECC_PointEncType_t pointEncType,
    mcuxClEcc_Weier_DomainParams_t *pEccWeierDomainParams)
{
    MCUXCLSESSION_ENTRY(pSession, mcuxClEcc_WeierECC_DecodePoint, diRefValue, MCUXCLECC_STATUS_FAULT_ATTACK);

    /* Call point decoding function specified by the point encoding type descriptor. */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_PointDecFct,
        pointEncType->pointDecFct(pSession,
                                  pEncodedPoint,
                                  pDecodedPoint,
                                  pointEncType,
                                  pEccWeierDomainParams));

    MCUXCLSESSION_EXIT(pSession, mcuxClEcc_WeierECC_DecodePoint, diRefValue, ret_PointDecFct, MCUXCLECC_STATUS_FAULT_ATTACK,
        pointEncType->pointDecFctFPId);
}
