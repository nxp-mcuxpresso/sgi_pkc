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

/** @file  mcuxClRsa_ComputeD.c
 *  @brief mcuxClRsa: function, which is called to compute private exponent d
 *         compliant with FIPS 186-4.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxClRsa.h>
#include <mcuxClKey.h>

#include <internal/mcuxClPkc_Internal.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClMath_Internal.h>
#include <internal/mcuxClPrng_Internal.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClSession_Internal_EntryExit.h>
#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_Internal_PkcTypes.h>
#include <internal/mcuxClRsa_ComputeD_FUP.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_ComputeD)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_ComputeD(
  mcuxClSession_Handle_t           pSession,
  mcuxClRsa_KeyEntry_t *           pE,
  mcuxClRsa_KeyEntry_t *           pP,
  mcuxClRsa_KeyEntry_t *           pQ,
  mcuxClRsa_KeyEntry_t *           pD,
  const uint32_t                  keyBitLength
  )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_ComputeD);

    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pP->keyEntryLength, MCUXCLRSA_MIN_MODLEN / 2u, MCUXCLRSA_MAX_MODLEN / 2u, MCUXCLRSA_STATUS_INVALID_INPUT)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pE->keyEntryLength, 3u, 32u, MCUXCLRSA_STATUS_INVALID_INPUT /* e is in the range 2^16 < e < 2^256 */)

    /*
     * Initialization:
     * - allocate buffers in PKC RAM
     * - update session (PKC workarea used...)
     */
    /* Size definitions */

    const uint32_t blindLen = MCUXCLRSA_INTERNAL_MOD_BLINDING_SIZE;  // length in bytes of the random value used for blinding
    const uint32_t blindAlignLen = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(blindLen);

    const uint32_t byteLenPQ = pP->keyEntryLength;  // P and Q have the same byte length
    const uint32_t primePQAlignLen = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(byteLenPQ);
    const uint32_t blindedPrimePQAlignLen = primePQAlignLen + blindAlignLen;

    const uint32_t keyLen = byteLenPQ * 2u;  // LCM have 2 times length of PQ
    const uint32_t keyAlignLen = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(keyLen);
    const uint32_t BlindedKeyAlignLen = keyAlignLen + blindAlignLen;

    uint32_t bufferSizeTotal = BlindedKeyAlignLen + 2u*MCUXCLRSA_PKC_WORDSIZE /* Lcm_b, equal to (2u*blindedPrimePQAlignLen + MCUXCLRSA_PKC_WORDSIZE) for mcuxClMath_ExactDivide and mcuxClRsa_ModInv */
                               + BlindedKeyAlignLen + MCUXCLRSA_PKC_WORDSIZE /* Phi_b, equal to (2u*blindedPrimePQAlignLen) for mcuxClRsa_ComputeD_Steps3_FUP and mcuxClRsa_ModInv */
                               + MCUXCLRSA_PKC_WORDSIZE /* Rnd */
                               + 2u * (BlindedKeyAlignLen + MCUXCLRSA_PKC_WORDSIZE); /* T0 and T1. PSub1, QSub1, PSub1_b and QSub1_b will reuse it */

    uint8_t *pPkcWorkarea = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, bufferSizeTotal / (sizeof(uint32_t)));

    uint8_t *pLcm_b = pPkcWorkarea;
    uint8_t *pPhi_b = pLcm_b + 2u*blindedPrimePQAlignLen + MCUXCLRSA_PKC_WORDSIZE;
    uint8_t *pRnd = pPhi_b + 2u*blindedPrimePQAlignLen;
    uint8_t *pPSub1 = pRnd + MCUXCLRSA_PKC_WORDSIZE;
    uint8_t *pQSub1 = pPSub1 + primePQAlignLen;
    uint8_t *pPSub1_b = pQSub1 + primePQAlignLen;
    uint8_t *pQSub1_b = pPSub1_b + blindedPrimePQAlignLen;
    uint8_t *pT0 = pPSub1;
    uint8_t *pT1 = pPSub1 + BlindedKeyAlignLen + MCUXCLRSA_PKC_WORDSIZE;

    /* Setup UPTR table */
    const uint32_t cpuWaSizeWord = MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLRSA_INTERNAL_COMPD_UPTRT_SIZE * (sizeof(uint16_t)));
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES("16-bit UPTRT table is assigned in CPU workarea")
    uint16_t * pOperands = (uint16_t *) mcuxClSession_allocateWords_cpuWa(pSession, cpuWaSizeWord);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_REINTERPRET_MEMORY_BETWEEN_INAPT_ESSENTIAL_TYPES()

    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_P]         = MCUXCLPKC_PTR2OFFSET(pP->pKeyEntryData);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_Q]         = MCUXCLPKC_PTR2OFFSET(pQ->pKeyEntryData);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_D]         = MCUXCLPKC_PTR2OFFSET(pD->pKeyEntryData);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_E]         = MCUXCLPKC_PTR2OFFSET(pE->pKeyEntryData);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_LCM_B]     = MCUXCLPKC_PTR2OFFSET(pLcm_b);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PHI_B]     = MCUXCLPKC_PTR2OFFSET(pPhi_b);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_RND]       = MCUXCLPKC_PTR2OFFSET(pRnd);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PSUB1]     = MCUXCLPKC_PTR2OFFSET(pPSub1);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1]     = MCUXCLPKC_PTR2OFFSET(pQSub1);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PSUB1_B]   = MCUXCLPKC_PTR2OFFSET(pPSub1_b);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1_B]   = MCUXCLPKC_PTR2OFFSET(pQSub1_b);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_T0]        = MCUXCLPKC_PTR2OFFSET(pT0);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_T1]        = MCUXCLPKC_PTR2OFFSET(pT1);
    pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_CONSTANT]  = 1u;

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pRnd is 32-bit aligned.")
    uint32_t *pR32 = (uint32_t *)pRnd;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    pR32[0] = mcuxClPrng_generate_word() | 0x1u;
    pR32[1] = 0u;

    /* Backup Ps1 length and UPTRT to recover in the end */
    uint16_t *pUptrtBak = MCUXCLPKC_GETUPTRT();
    uint32_t backupPs1LenReg = MCUXCLPKC_PS1_GETLENGTH_REG();
    /* Set UPTRT table */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_SETUPTRT(pOperands);

    /*
     * call the FUP code to do the below steps
     * 1. Compute (p-1)*b
     * 2. Compute (q-1)*b
     * 3. Compute lcm((p-1)*b,(q-1)*b) = (((p-1)*b)*((q-1)*b)) / gcd((p-1)*b,(q-1)*b)
     * 3.1 Compute phi_b = ((p-1)*b)*((q-1)*b)
     * 3.2 Compute gcd_b = gcd((p-1)*b,(q-1)*b)
     */
    MCUXCLPKC_PS1_SETLENGTH(primePQAlignLen, primePQAlignLen);
    MCUXCLPKC_PS2_SETLENGTH(primePQAlignLen, MCUXCLRSA_PKC_WORDSIZE);
    MCUXCLPKC_FP_CALCFUP(mcuxClRsa_ComputeD_Steps12_FUP, mcuxClRsa_ComputeD_Steps12_FUP_LEN);

    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS2_SETLENGTH(blindedPrimePQAlignLen, blindedPrimePQAlignLen);
    MCUXCLPKC_FP_CALCFUP(mcuxClRsa_ComputeD_Steps3_FUP, mcuxClRsa_ComputeD_Steps3_FUP_LEN);

    /* Protect the addresses of P and Q */
    MCUX_CSSL_DI_EXPUNGE(inputParams, MCUXCLPKC_OFFSET2PTR(pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_P]));
    MCUX_CSSL_DI_EXPUNGE(inputParams, MCUXCLPKC_OFFSET2PTR(pOperands[MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_Q]));

    MCUXCLPKC_WAITFORFINISH();
    MCUX_CSSL_FP_FUNCTION_CALL(leadingZeroN, mcuxClMath_LeadingZeros(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1_B));
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(leadingZeroN, 0u, blindedPrimePQAlignLen, MCUXCLRSA_STATUS_INVALID_INPUT)
    uint32_t realBlindedGcdByteLen = blindedPrimePQAlignLen - (leadingZeroN >> 3u);

    /*
     * 3.3 Compute lcm(p-1, q-1)*b = phi_b/gcd_b
     *
     * Used functions: mcuxClMath_ExactDivide
     */
    MCUXCLPKC_PS1_SETLENGTH(0u, 2u*MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(blindedPrimePQAlignLen));
    MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_LCM_B, 0u);
    MCUXCLPKC_WAITFORFINISH();
    MCUXCLMATH_FP_EXACTDIVIDE(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_LCM_B,
                        MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PHI_B,
                        MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_QSUB1_B,
                        MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PSUB1, // as temp buffer
                        2u*MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(blindedPrimePQAlignLen),
                        MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(realBlindedGcdByteLen));

    /*
     * 4. Compute d := e^(-1) mod lcm(p-1, q-1) in a blinded way
     *
     * Used functions: mcuxClRsa_ModInv
     */
    MCUXCLPKC_PS1_SETLENGTH(0u, BlindedKeyAlignLen);
    const uint32_t eAlignLen = MCUXCLRSA_ALIGN_TO_PKC_WORDSIZE(pE->keyEntryLength);
    MCUXCLPKC_PS2_SETLENGTH(0, eAlignLen);
    /* Clear the PHI buffer */
    MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PHI_B, 0u);
    /* Copy e to the PHI buffer (the content pointed by pE should not be destroyed) */
    MCUXCLPKC_FP_CALC_OP2_OR_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PHI_B, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_E, 0u);

    /* Call mcuxClRsa_ModInv. Note that it expunges pD->pKeyEntryData from DI. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClRsa_ModInv(MCUXCLPKC_PACKARGS4(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_D,
                                                      MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PHI_B,
                                                      MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_LCM_B,
                                                      MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_RND),
                                                      MCUXCLPKC_PACKARGS2(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_T1,
                                                      MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_T0),
                                                      eAlignLen, BlindedKeyAlignLen));

    pD->keyEntryLength = keyBitLength >> 3u;

    /*
     * 5. Verify FIPS 186-4 condition on lower bound of d
     *    If d <= 2^(nlen/2), then function returns MCUXCLRSA_STATUS_INTERNAL_PRIVEXP_INVALID error.
     *
     * Used functions: PKC operation.
     */
    /* Clear buffers phi, its length is nlen */
    MCUXCLPKC_PS1_SETLENGTH(0u, keyAlignLen);
    MCUXCLPKC_FP_CALC_OP1_CONST(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PHI_B, 0u);
    MCUXCLPKC_WAITFORFINISH();

    uint32_t idx = (keyBitLength >> 1u) >> 3u;
    uint32_t lowBoundByte = ((uint32_t)1u << ((keyBitLength >> 1u) & 7u));
    pPhi_b[idx] = (uint8_t)(lowBoundByte & 0xFFu);
    MCUXCLPKC_FP_CALC_OP1_CMP(MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_PHI_B, MCUXCLRSA_INTERNAL_UPTRTINDEX_COMPD_D);

    /* Protect input keyBitLength */
    MCUX_CSSL_DI_EXPUNGE(inputParams, keyBitLength);

    /* Recover session, Ps1 length and Uptrt */
    mcuxClSession_freeWords_pkcWa(pSession, bufferSizeTotal / (sizeof(uint32_t)));
    mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
    MCUXCLPKC_WAITFORFINISH();
    MCUXCLPKC_PS1_SETLENGTH_REG(backupPs1LenReg);
    MCUXCLPKC_SETUPTRT(pUptrtBak);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_ComputeD,
            ((MCUXCLPKC_FLAG_CARRY != MCUXCLPKC_WAITFORFINISH_GETCARRY()) ? MCUXCLRSA_STATUS_INTERNAL_PRIVEXP_INVALID : MCUXCLRSA_STATUS_KEYGENERATION_OK),
            2u*MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_LeadingZeros),
            MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ExactDivide),
            MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
            MCUXCLPKC_FP_CALLED_CALC_OP2_OR_CONST,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_ModInv),
            MCUXCLPKC_FP_CALLED_CALC_OP1_CONST,
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP
            );
}
