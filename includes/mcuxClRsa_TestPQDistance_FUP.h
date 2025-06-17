/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2023-2024 NXP                                            */
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

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClPkc_FupMacros.h>
#include <internal/mcuxClRsa_TestPQDistance_FUP.h>

MCUXCLPKC_FUP_EXT_ROM(mcuxClRsa_TestPQDistance_FUP,
    FUP_CRC_PLACEHOLDER,
    /* 1. Xor 128 MSbits of p with rand */
    FUP_OP1_XOR(MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T1,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_P128MSB,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_RAND),
    /* 2. Xor 128 MSbits of q with rand */
    FUP_OP1_XOR(MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T2,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_Q128MSB,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_RAND),
    /* 3. Copy 100 MSbits of masked p into buffer in PKC RAM */
    FUP_OP1_SHR(MCUXCLRSA_INTERNAL_TESTPQDISTANCE_RAND,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T1,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_CONSTANT28),
    /* 4. Copy 100 MS bits of masked q into buffer in PKC RAM */
    FUP_OP1_SHR(MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T1,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T2,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_CONSTANT28),
    /*
    * 5. Compare 100 MSbits of p and q in a masked way
    *    If they are equal, then function returns MCUXCLRSA_STATUS_INVALID_INPUT error code
    *    (primes do not meet the FIPS requirements).
    */
    FUP_OP1_CMP(MCUXCLRSA_INTERNAL_TESTPQDISTANCE_RAND,
        MCUXCLRSA_INTERNAL_TESTPQDISTANCE_T1),
);
