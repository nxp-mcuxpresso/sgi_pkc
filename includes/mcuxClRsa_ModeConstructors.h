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

#ifndef MCUXCLRSA_MODECONSTRUCTORS_H_
#define MCUXCLRSA_MODECONSTRUCTORS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxCsslFlowProtection.h>

#include <mcuxClSignature_Types.h>


#include <mcuxClKey_Types.h>
#include <mcuxClHash_Types.h>
#include <mcuxClBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************/
/* Descriptors of mcuxClRsa APIs                           */
/**********************************************************/
/**
 * @defgroup mcuxClRsa_Descriptors mcuxClRsa_Descriptors
 * @brief Defines descriptors of @ref mcuxClRsa
 * @ingroup mcuxClRsa
 * @{
 */
/**
 * \defgroup clRsaSignatureModes Signature RSA mode definitions
 * \brief Modes used by the Signature operations with RSA.
 * \ingroup clSignatureModes
 * @{
 */

/**
 * @brief RSA signature protocol descriptor structure
 *
 * This structure captures all the information that the Signature interfaces need
 * to know about RSA-specific operations.
 */
struct mcuxClRsa_Signature_ProtocolDescriptor;
typedef struct mcuxClRsa_Signature_ProtocolDescriptor mcuxClRsa_SignatureProtocolDescriptor_t;

/**
 * \brief Mode constructor for RSASSA-PSS signature generation and verification
 *
 * \param pSignatureMode      Pointer to a mode descriptor that will be updated by this function.
 * \param pProtocolDescriptor Pointer to an RSA protocol descriptor that will be updated by this function.
 * \param hashAlgorithm       Hash algorithm that should be used.
 * \param saltLength          Number of bytes of the salt.
 * \param options             RSA options:
 *                            - MCUXCLRSA_OPTION_VERIFY_NOHWACC: perform pure SW verification, without using HW acceleration
 *
 * \pre
 * - The RNG context must be initialized before performing an RSA signature generation with RSASSA-PSS.
 *
 * \implements{REQ_788249,REQ_788250,REQ_788253}
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRsa_SignatureModeConstructor_RSASSA_PSS)
void mcuxClRsa_SignatureModeConstructor_RSASSA_PSS(
  mcuxClSignature_ModeDescriptor_t * pSignatureMode,
  mcuxClRsa_SignatureProtocolDescriptor_t * pProtocolDescriptor,
  mcuxClHash_Algo_t hashAlgorithm,
  uint32_t saltLength,
  uint32_t options
);

/**
 * \brief Mode constructor for RSASSA-PKCS1-v1_5 signature generation and verification
 *
 * \param pSignatureMode      Pointer to a mode descriptor that will be updated by this function.
 * \param pProtocolDescriptor Pointer to an RSA protocol descriptor that will be updated by this function.
 * \param hashAlgorithm       Hash algorithm that should be used.
 * \param options             RSA options:
 *                            - MCUXCLRSA_OPTION_VERIFY_NOHWACC: perform pure SW verification, without using HW acceleration
 *
 * \implements{REQ_788249,REQ_788250,REQ_788252}
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRsa_SignatureModeConstructor_RSASSA_PKCS1_v1_5)
void mcuxClRsa_SignatureModeConstructor_RSASSA_PKCS1_v1_5(
  mcuxClSignature_ModeDescriptor_t * pSignatureMode,
  mcuxClRsa_SignatureProtocolDescriptor_t * pProtocolDescriptor,
  mcuxClHash_Algo_t hashAlgorithm,
  uint32_t options
);


/** @} */


/**
 * \defgroup mcuxClRsa_KeyGeneration_ModeDescriptor Key Generation RSA mode descriptor
 * \brief RSA key generation mode descriptor.
 * \details RSA key generation related defines used construct the mode descriptor used by @ref mcuxClKey_generate_keypair
 *  function.
 * \ingroup mcuxClRsa_KeyGeneration_ModeDescriptor
 * @{
 */

MCUX_CSSL_ANALYSIS_START_PATTERN_URL_IN_COMMENTS()
/**
 * \brief Mode constructor for RSA key generation algorithm.
 *
 * \details
 *         This function can be used to create mode descriptor used by @ref mcuxClKey_generate_keypair function.
 *         This mode shall be used to realize RSA key generation operation according to FIPS 186-4
 *         (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf), in particular:
 *         <ul>
 *             <li>method provided in Appendix B.3.3 used for the generation of the random primes p and q
 *                  that are probably prime;</li>
 *             <li>public exponent e, primes p and q and private exponent d meet the criteria specified
 *                 in Appendix B.3.1. According to the criteria the exponent e is restricted to odd values
 *                 in the range \f$(2^{16}<e<2^{256})\f$.</li>
 *             <li>primes p and q are generated using probabilistic primality test with the error probability
 *                 lower than \f$2^{-125}\f$. The number of Miller-Rabin test iterations is consistent with the
 *                 SOGIS Agreed Cryptographic Mechanisms version 1.2.
 *                 (https://www.sogis.eu/documents/cc/crypto/SOGIS-Agreed-Cryptographic-Mechanisms-1.2.pdf) </li>
 *         </ul>
 *         To be able to perform an key generation using  @ref mcuxClKey_generate_keypair and this mode:
 *         <ul>
 *            <li>Session must be initialized with workareas for CPU and PKC operations that considers the workareas
 *                required by this mode for the given key type and size (see @ref MCUXCLRSA_KEYGENERATION_PLAIN_WA and
 *                @ref MCUXCLRSA_KEYGENERATION_CRT_WA).</li>
 *            <li>RNG context must be initialized using mode @ref mcuxClRandomModes_Constants which will ensure the entropy level
 *                (security strength) in accordance with the generated key size, as specified in SP 800-57, Part 1.</li>
 *            <li>Handle of private key must be properly initialized  with @ref mcuxClKey_init function using:</li>
 *            <ul>
 *               <li>appropriate RSA private @ref mcuxClRsa_KeyTypes_Descriptors;</li>
 *               <li>pointer to key data buffer where the generated private key will be stored. The buffer shall be allocated using
 *                   pre-define sizes @ref MCUXCLRSA_KEYGENERATION_KEY_DATA_SIZE for the given key type and key size.</li>
 *            </ul>
 *            <li>Handle of public key must be properly initialized  with @ref mcuxClKey_init function using:</li>
 *            <ul>
 *               <li>appropriate RSA public @ref mcuxClRsa_KeyTypes_Descriptors;</li>
 *               <li>pointer to key data buffer where the generated public key will be stored.  The buffer shall be allocated using
 *                   pre-define sizes @ref MCUXCLRSA_KEYGENERATION_KEY_DATA_SIZE for the given key type and key size.</li>
 *            </ul>
 *            <li>pointers to key data buffers and key handle must be aligned to CPU word size</li>
 *         </ul>
 *
 * \note   There are the following deviations were applied from the algorithm specified in Appendix B.3.3 of FIPS 186-4:
 * \note   \li Primes p and q are chosen to be congruent \f$3\mod4\f$.\n
 *             Rationale: With this additional restriction on p and q a generated key is still compatible with FIPS 186-4.
 *             Such primes and their products have properties that simplify algorithms, for example step 4.5 in Miller-Rabin test
 *             described in Appendix C.3.1 can be skipped (due to fact that a=1). This restriction has positive impact on the security,
 *             performance, and code size. This approach was also accepted in other products.
 * \note   \li Checks performed in steps 4.4 and 5.5 are done using only 64 most significant bits of the value
 *             specified by the expression \f$(\sqrt{2})(2^{(nlen/2)–1})\f$ and rounded up, it is 0xb504f333f9de6485.\n
 *             Rationale: This deviation is acceptable as it is a stronger condition.
 * \note   \li Check performed in step 5.4 (check if \f$|p–q| <= 2^{nlen/2–100}\f$) is performed after q is generated,
 *             it is after testing that q it probably prime. If p and q does not meet this FIPS requirements, no new
 *             prime q number will be generated. Instead the function ends with @ref MCUXCLKEY_STATUS_FAULT_ATTACK error.\n
 *             Rationale: This inequality occurs with a very small probability and it's usually treated
 *             as a hardware failure (this handling has been approved by InfoGard and NIST).
 * \note   \li The pre-check against products of small primes is applied before the steps 4.5 and 5.6 respectively.
 * \note       If an event occurs that \f$d <= 2^{nlen/2}\f$ then only a new q will be generated.
 * \attention  To support all required key lengths, this implementation does not verify that key length meets the FIPS 186-4 criteria
 *              (i.e., no check whether the key size is 2048 or 3072 bits).
 *              User shall ensure that if FIPS 186-4 compliance is claimed, this mode is used to generate keys of 2048 or 3072 bits only.
 * \attention  If the key generation operation returns Error or Fault (through session), the user shall ensure that the generated key is
 *              cleared and not used.
 *
 * \param [out] pKeyGenMode         Pointer to a mode descriptor to be initialized for RSA key pair generation with public exponent input.
 * \param [in]  pE                  Pointer to the input public exponent e. It must be odd values
 *                                  in the range \f$2^{16}<e<2^{256}\f$.
 * \param [in]  eLength             Length of the public exponent e.
 *
 * \return void
 *
 * \pre
 * Before calling this function, sufficient space should be allocated for the key mode descriptor and RSA-specific content,
 * using the macro @ref MCUXCLRSA_KEYGEN_MODE_SIZE.
 *
 * \implements{REQ_788251}
 */
MCUX_CSSL_ANALYSIS_STOP_PATTERN_URL_IN_COMMENTS()
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRsa_KeyGeneration_ModeConstructor)
void mcuxClRsa_KeyGeneration_ModeConstructor(
  mcuxClKey_GenerationDescriptor_t * pKeyGenMode,
  const uint8_t * pE,
  uint32_t eLength
);
/** @} */
/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLRSA_MODECONSTRUCTORS_H_ */
