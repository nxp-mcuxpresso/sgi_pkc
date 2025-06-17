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

#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_Internal_Types.h>


MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile mcuxClRsa_SignatureProtocolDescriptor_t mcuxClRsa_Signature_ProtocolDescriptor_size;

#include <internal/mcuxClKey_Internal.h>
volatile uint8_t mcuxClRsa_KeyGeneration_ProtocolDescriptor_size[sizeof(mcuxClKey_GenerationDescriptor_t) + sizeof(mcuxClRsa_KeyGeneration_ProtocolDescriptor_t)];


/****************************************************************************/
/* Computation of workarea sizes for the Rsa_sign function.               */
/****************************************************************************/

volatile uint8_t mcuxClRsa_Sign_Plain_NoEMSA_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOEMSA_WACPU_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_NoEMSA_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOEMSA_WACPU_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_NoEMSA_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOEMSA_WACPU_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_NoEMSA_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOEMSA_WACPU_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_Sign_Plain_Pkcs1v15Encode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_Pkcs1v15Encode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_Pkcs1v15Encode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_Pkcs1v15Encode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_Sign_Plain_PssEncode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_PssEncode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_PssEncode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_PssEncode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(4096/8)];

typedef union
{
    uint8_t mcuxClRsa_Internal_Sign_Plain_PKCS1V15Encode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WAPKC_SIZE(1024/8)];
    uint8_t mcuxClRsa_Internal_Sign_Plain_PSSEncode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WAPKC_SIZE(1024/8)];
    uint8_t mcuxClRsa_Internal_Sign_Plain_NoEMSA_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOEMSA_WAPKC_SIZE(1024/8)];
} mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Plain_PrimeByteLength_1024_t;
#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE_1024 (sizeof(mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Plain_PrimeByteLength_1024_t))
volatile uint8_t mcuxClRsa_Sign_Plain_1024_WaPKC[MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE_1024];
typedef union
{
    uint8_t mcuxClRsa_Internal_Sign_Plain_PKCS1V15Encode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WAPKC_SIZE(2048/8)];
    uint8_t mcuxClRsa_Internal_Sign_Plain_PSSEncode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WAPKC_SIZE(2048/8)];
    uint8_t mcuxClRsa_Internal_Sign_Plain_NoEMSA_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOEMSA_WAPKC_SIZE(2048/8)];
} mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Plain_PrimeByteLength_2048_t;
#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE_2048  (sizeof(mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Plain_PrimeByteLength_2048_t))
volatile uint8_t mcuxClRsa_Sign_Plain_2048_WaPKC[MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE_2048];
typedef union
{
    uint8_t mcuxClRsa_Internal_Sign_Plain_PKCS1V15Encode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WAPKC_SIZE(3072/8)];
    uint8_t mcuxClRsa_Internal_Sign_Plain_PSSEncode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WAPKC_SIZE(3072/8)];
    uint8_t mcuxClRsa_Internal_Sign_Plain_NoEMSA_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOEMSA_WAPKC_SIZE(3072/8)];
} mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Plain_PrimeByteLength_3072_t;
#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE_3072  (sizeof(mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Plain_PrimeByteLength_3072_t))
volatile uint8_t mcuxClRsa_Sign_Plain_3072_WaPKC[MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE_3072];
typedef union
{
    uint8_t mcuxClRsa_Internal_Sign_Plain_PKCS1V15Encode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WAPKC_SIZE(4096/8)];
    uint8_t mcuxClRsa_Internal_Sign_Plain_PSSEncode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WAPKC_SIZE(4096/8)];
    uint8_t mcuxClRsa_Internal_Sign_Plain_NoEMSA_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOEMSA_WAPKC_SIZE(4096/8)];
} mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Plain_PrimeByteLength_4096_t;
#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE_4096  (sizeof(mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Plain_PrimeByteLength_4096_t))
volatile uint8_t mcuxClRsa_Sign_Plain_4096_WaPKC[MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE_4096];

volatile uint8_t mcuxClRsa_Sign_CRT_NoEMSA_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_NOEMSA_WACPU_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_NoEMSA_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_NOEMSA_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_NoEMSA_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_NOEMSA_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_NoEMSA_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_NOEMSA_WACPU_SIZE(4096/8/2)];

volatile uint8_t mcuxClRsa_Sign_CRT_Pkcs1v15Encode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_Pkcs1v15Encode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_Pkcs1v15Encode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_Pkcs1v15Encode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(4096/8/2)];

volatile uint8_t mcuxClRsa_Sign_CRT_PssEncode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_PssEncode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_PssEncode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_PssEncode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(4096/8/2)];

typedef union
{
    uint8_t mcuxClRsa_Internal_Sign_Crt_PKCS1V15Encode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WAPKC_SIZE(1024/8/2)];
    uint8_t mcuxClRsa_Internal_Sign_Crt_PSSEncode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WAPKC_SIZE(1024/8/2)];
    uint8_t mcuxClRsa_Internal_Sign_Crt_NoEMSA_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_NOEMSA_WAPKC_SIZE(1024/8/2)];
} mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Crt_PrimeByteLength_1024_t;
#define MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE_1024  (sizeof(mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Crt_PrimeByteLength_1024_t))
volatile uint8_t mcuxClRsa_Sign_CRT_1024_WaPKC[MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE_1024];
typedef union
{
    uint8_t mcuxClRsa_Internal_Sign_Crt_PKCS1V15Encode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WAPKC_SIZE(2048/8/2)];
    uint8_t mcuxClRsa_Internal_Sign_Crt_PSSEncode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WAPKC_SIZE(2048/8/2)];
    uint8_t mcuxClRsa_Internal_Sign_Crt_NoEMSA_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_NOEMSA_WAPKC_SIZE(2048/8/2)];
} mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Crt_PrimeByteLength_2048_t;
#define MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE_2048  (sizeof(mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Crt_PrimeByteLength_2048_t))
volatile uint8_t mcuxClRsa_Sign_CRT_2048_WaPKC[MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE_2048];
typedef union
{
    uint8_t mcuxClRsa_Internal_Sign_Crt_PKCS1V15Encode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WAPKC_SIZE(3072/8/2)];
    uint8_t mcuxClRsa_Internal_Sign_Crt_PSSEncode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WAPKC_SIZE(3072/8/2)];
    uint8_t mcuxClRsa_Internal_Sign_Crt_NoEMSA_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_NOEMSA_WAPKC_SIZE(3072/8/2)];
} mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Crt_PrimeByteLength_3072_t;
#define MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE_3072  (sizeof(mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Crt_PrimeByteLength_3072_t))
volatile uint8_t mcuxClRsa_Sign_CRT_3072_WaPKC[MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE_3072];
typedef union
{
    uint8_t mcuxClRsa_Internal_Sign_Crt_PKCS1V15Encode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WAPKC_SIZE(4096/8/2)];
    uint8_t mcuxClRsa_Internal_Sign_Crt_PSSEncode_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WAPKC_SIZE(4096/8/2)];
    uint8_t mcuxClRsa_Internal_Sign_Crt_NoEMSA_WaPkc_Size[MCUXCLRSA_INTERNAL_SIGN_CRT_NOEMSA_WAPKC_SIZE(4096/8/2)];
} mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Crt_PrimeByteLength_4096_t;
#define MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE_4096  (sizeof(mcuxClRsa_Internal_MaxUnion_WaPkc_Sign_Crt_PrimeByteLength_4096_t))
volatile uint8_t mcuxClRsa_Sign_CRT_4096_WaPKC[MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE_4096];


/****************************************************************************/
/* Computation of workarea sizes for the   function.               */
/****************************************************************************/

volatile uint8_t mcuxClRsa_Verify_Compare_NoEMSA_Verify_WaCPU[MCUXCLRSA_INTERNAL_VERIFY_COMPARE_NOEMSA_VERIFY_WACPU_SIZE];

volatile uint8_t mcuxClRsa_Verify_Pkcs1v15Verify_WaCPU[MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WACPU_SIZE];

volatile uint8_t mcuxClRsa_Verify_PssVerify_WaCPU[MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WACPU_SIZE];

typedef union
{
    uint8_t mcuxClRsa_Internal_Verify_PKCS1V15Verify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WAPKC_SIZE(1024u/8u)];
    uint8_t mcuxClRsa_Internal_Verify_PSSVerify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WAPKC_SIZE(1024u/8u)];
    uint8_t mcuxClRsa_Internal_Verify_Compare_NoEMSA_Verify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_COMPARE_NOEMSA_VERIFY_WAPKC_SIZE(1024u/8u)];
} mcuxClRsa_Internal_MaxUnion_Verify_WaPkc_1024_t;
#define MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE_1024 (sizeof(mcuxClRsa_Internal_MaxUnion_Verify_WaPkc_1024_t))
volatile uint8_t mcuxClRsa_Verify_1024_WaPKC[MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE_1024];
typedef union
{
    uint8_t mcuxClRsa_Internal_Verify_PKCS1V15Verify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WAPKC_SIZE(2048u/8u)];
    uint8_t mcuxClRsa_Internal_Verify_PSSVerify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WAPKC_SIZE(2048u/8u)];
    uint8_t mcuxClRsa_Internal_Verify_Compare_NoEMSA_Verify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_COMPARE_NOEMSA_VERIFY_WAPKC_SIZE(2048u/8u)];
} mcuxClRsa_Internal_MaxUnion_Verify_WaPkc_2048_t;
#define MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE_2048 (sizeof(mcuxClRsa_Internal_MaxUnion_Verify_WaPkc_2048_t))
volatile uint8_t mcuxClRsa_Verify_2048_WaPKC[MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE_2048];
typedef union
{
    uint8_t mcuxClRsa_Internal_Verify_PKCS1V15Verify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WAPKC_SIZE(3072u/8u)];
    uint8_t mcuxClRsa_Internal_Verify_PSSVerify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WAPKC_SIZE(3072u/8u)];
    uint8_t mcuxClRsa_Internal_Verify_Compare_NoEMSA_Verify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_COMPARE_NOEMSA_VERIFY_WAPKC_SIZE(3072u/8u)];
} mcuxClRsa_Internal_MaxUnion_Verify_WaPkc_3072_t;
#define MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE_3072 (sizeof(mcuxClRsa_Internal_MaxUnion_Verify_WaPkc_3072_t))
volatile uint8_t mcuxClRsa_Verify_3072_WaPKC[MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE_3072];
typedef union
{
    uint8_t mcuxClRsa_Internal_Verify_PKCS1V15Verify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WAPKC_SIZE(4096u/8u)];
    uint8_t mcuxClRsa_Internal_Verify_PSSVerify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WAPKC_SIZE(4096u/8u)];
    uint8_t mcuxClRsa_Internal_Verify_Compare_NoEMSA_Verify_WaPkc_Size[MCUXCLRSA_INTERNAL_VERIFY_COMPARE_NOEMSA_VERIFY_WAPKC_SIZE(4096u/8u)];
} mcuxClRsa_Internal_MaxUnion_Verify_WaPkc_4096_t;
#define MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE_4096 (sizeof(mcuxClRsa_Internal_MaxUnion_Verify_WaPkc_4096_t))
volatile uint8_t mcuxClRsa_Verify_4096_WaPKC[MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE_4096];


/*************************************************************************************************************************/
/* Computation of key data size for the mcuxClRsa_Util_KeyGeneration_Crt and mcuxClRsa_Util_KeyGeneration_Plain functions. */
/*************************************************************************************************************************/
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_Key_Data_1024[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_Key_Data_2048[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_Key_Data_3072[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_Key_Data_4096[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_KeyGeneration_Crt_Key_Data_1024[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRT_DATA_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_Key_Data_2048[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRT_DATA_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_Key_Data_3072[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRT_DATA_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_Key_Data_4096[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRT_DATA_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_KeyGeneration_CrtDfa_Key_Data_1024[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRTDFA_DATA_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_CrtDfa_Key_Data_2048[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRTDFA_DATA_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_CrtDfa_Key_Data_3072[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRTDFA_DATA_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_CrtDfa_Key_Data_4096[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_CRTDFA_DATA_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_KeyData_Plain_t_Size[sizeof(mcuxClRsa_KeyData_Plain_t)];
volatile uint8_t mcuxClRsa_KeyGeneration_Public_Key_Data_1024[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Public_Key_Data_2048[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Public_Key_Data_3072[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Public_Key_Data_4096[MCUXCLRSA_INTERNAL_KEYGENERATION_KEYPAIR_PLAIN_DATA_SIZE(4096/8)];

/***********************************************************************************************************/
/* Computation of workarea sizes for the mcuxClRsa_Util_KeyGeneration_Plain function for typical key sizes. */
/***********************************************************************************************************/
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_1024_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WAPKC_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_2048_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WAPKC_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_3072_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WAPKC_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_4096_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WAPKC_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_KeyGeneration_Plain_1024_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_2048_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_3072_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_4096_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE(4096/8)];
/*********************************************************************************************************/
/* Computation of workarea sizes for the mcuxClRsa_Util_KeyGeneration_Crt function for typical key sizes. */
/*********************************************************************************************************/
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_1024_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WAPKC_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_2048_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WAPKC_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_3072_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WAPKC_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_4096_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WAPKC_SIZE(4096/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_1024_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_2048_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_3072_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_4096_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE(4096/8/2)];


MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
