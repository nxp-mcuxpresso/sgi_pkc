/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
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
#include <internal/mcuxClHash_Internal.h>

/**********************************************************/
/* Hash Algorithm OIDs                                    */
/**********************************************************/
const uint8_t mcuxClHash_oidSha2_224[] __attribute__((section(".rodata.hash.oid"))) =
{
  // OID: 2.16.840.1.101.3.4.2.4
  0x30U, 0x2dU, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x04U, 0x05U, 0x00U, 0x04U, 0x1cU
};

const uint8_t mcuxClHash_oidSha2_256[] __attribute__((section(".rodata.hash.oid"))) =
{
  // OID: 2.16.840.1.101.3.4.2.1
  0x30U, 0x31U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x01U, 0x05U, 0x00U, 0x04U, 0x20U
};

const uint8_t mcuxClHash_oidSha2_384[] __attribute__((section(".rodata.hash.oid"))) =
{
  // OID: 2.16.840.1.101.3.4.2.2
  0x30U, 0x41U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x02U, 0x05U, 0x00U, 0x04U, 0x30U
};

const uint8_t mcuxClHash_oidSha2_512[] __attribute__((section(".rodata.hash.oid"))) =
{
  // OID: 2.16.840.1.101.3.4.2.3
  0x30U, 0x51U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x03U, 0x05U, 0x00U, 0x04U, 0x40U
};





#ifdef MCUXCL_FEATURE_HASH_C_SHA1
const uint8_t mcuxClHash_oidSha1[] __attribute__((section(".rodata.hash.oid"))) =
{
  // OID: 1.3.14.3.2.26
  0x30U, 0x21U, 0x30U, 0x09U, 0x06U, 0x05U, 0x2bU, 0x0eU, 0x03U, 0x02U, 0x1aU, 0x05U, 0x00U, 0x04U, 0x14U
};
#endif /* MCUXCL_FEATURE_HASH_C_SHA1 */
