package web5.sdk.crypto

import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.subtle.Ed25519Verify
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.crypto.Ed25519.PRIV_MULTICODEC
import web5.sdk.crypto.Ed25519.PUB_MULTICODEC
import web5.sdk.crypto.Ed25519.algorithm
import web5.sdk.crypto.jwk.Jwk
import java.security.GeneralSecurityException
import java.security.SignatureException

/**
 * Implementation of the [KeyGenerator] and [Signer] interfaces, specifically utilizing
 * the Ed25519 elliptic curve digital signature algorithm. This implementation provides
 * functionality to generate key pairs, compute public keys from private keys, and
 * sign/verify messages utilizing Ed25519.
 *
 * ### Example Usage:
 * TODO: Insert example usage here.
 *
 * @property algorithm Specifies the JWS algorithm type. For Ed25519, this is `EdDSA`.
 * @property PUB_MULTICODEC A byte array representing the multicodec prefix for an Ed25519 public key.
 * @property PRIV_MULTICODEC A byte array representing the multicodec prefix for an Ed25519 private key.
 */

public object Ed25519 : KeyGenerator, Signer {
  override val algorithm: Jwa = Jwa.EdDSA
  override val curve: JwaCurve = JwaCurve.Ed25519
  override val keyType: String = "OKP"


  public const val PUB_MULTICODEC: Int = 0xed
  public const val PRIV_MULTICODEC: Int = 0x1300

  /**
   * Generates a private key utilizing the Ed25519 algorithm.
   *
   * @param options (Optional) Additional options to control the key generation process.
   * @return The generated private key in Jwk format.
   */
  override fun generatePrivateKey(options: KeyGenOptions?): Jwk {
    // todo use tink to generate private key?
    val privateKey = OctetKeyPairGenerator(Curve.Ed25519)
      .algorithm(JWSAlgorithm.EdDSA)
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()

    return Jwk.Builder()
      .algorithm(algorithm.name)
      .privateKey(privateKey.d.toString())
      .x(privateKey.x.toString())
      .keyUse("sig")
      .build()

  }

  /**
   * Derives the public key corresponding to a given private key.
   *
   * @param privateKey The private key in Jwk format.
   * @return The corresponding public key in Jwk format.
   */
  override fun computePublicKey(privateKey: Jwk): Jwk {
    require(privateKey.kty == "OKP") { "private key must be an Octet Key Pair (kty: OKP)" }

    return Jwk.Builder()
      .keyType(privateKey.kty)
      .algorithm(algorithm.name)
      .x(privateKey.x.toString())
      .build()
  }

  override fun privateKeyToBytes(privateKey: Jwk): ByteArray {
    validatePrivateKey(privateKey)

    return Convert(privateKey.d, EncodingFormat.Base64Url).toByteArray()
  }

  override fun publicKeyToBytes(publicKey: Jwk): ByteArray {
    validatePublicKey(publicKey)

    return Convert(publicKey.x, EncodingFormat.Base64Url).toByteArray()
  }

  override fun bytesToPrivateKey(privateKeyBytes: ByteArray): Jwk {
    val privateKeyParameters = Ed25519PrivateKeyParameters(privateKeyBytes, 0)
    val publicKeyBytes = privateKeyParameters.generatePublicKey().encoded

    val base64UrlEncodedPrivateKey = Convert(privateKeyBytes).toBase64Url()
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url()

    return Jwk.Builder()
      .keyType("OKP")
      .algorithm(algorithm.name)
      .privateKey(base64UrlEncodedPrivateKey)
      .x(base64UrlEncodedPublicKey)
      .keyUse("sig")
      .build()
  }

  override fun bytesToPublicKey(publicKeyBytes: ByteArray): Jwk {
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url()

    return Jwk.Builder()
      .keyType("OKP")
      .algorithm(algorithm.name)
      .x(base64UrlEncodedPublicKey)
      .keyUse("sig")
      .build()
  }

  override fun sign(privateKey: Jwk, payload: ByteArray, options: SignOptions?): ByteArray {
    validatePrivateKey(privateKey)

    val privateKeyBytes = privateKeyToBytes(privateKey)
    val signer = Ed25519Sign(privateKeyBytes)

    return signer.sign(payload)
  }

  override fun verify(publicKey: Jwk, signedPayload: ByteArray, signature: ByteArray, options: VerifyOptions?) {
    validatePublicKey(publicKey)

    val publicKeyBytes = publicKeyToBytes(publicKey)
    val verifier = Ed25519Verify(publicKeyBytes)

    try {
      verifier.verify(signature, signedPayload)
    } catch (e: GeneralSecurityException) {
      throw SignatureException(e.message, e)
    }
  }

  /**
   * Validates the provided [Jwk] (JSON Web Key) is a public key
   *
   * This function checks the following:
   * - The key must be a public key
   * - The key must be a valid Ed25519 key
   *
   * If any of these checks fail, this function throws an [IllegalArgumentException] with
   * a descriptive error message.
   *
   * @param key The [Jwk] to validate.
   * @throws IllegalArgumentException if the key is not a public key
   */
  public fun validatePublicKey(key: Jwk) {
    require(key.d == null) { "key must be public" }
    validateKey(key)
  }

  /**
   * Validates the provided [Jwk] (JSON Web Key) to ensure it conforms to the expected key type and format.
   *
   * This function checks the following:
   * - The key must be a private key
   * - The key must be a valid Ed25519 key
   *
   * If any of these checks fail, this function throws an [IllegalArgumentException] with
   * a descriptive error message.
   *
   * @param key The [Jwk] to validate.
   * @throws IllegalArgumentException if the key is not a private key
   */
  public fun validatePrivateKey(key: Jwk) {
    require(key.d != null) { "key must be private" }
    validateKey(key)
  }

  /**
   * Validates the provided [Jwk] (JSON Web Key) to ensure it conforms to the expected key type and format.
   *
   * This function checks the following:
   * - The key must be an instance of [OctetKeyPair].
   *
   * If any of these checks fail, this function throws an [IllegalArgumentException] with
   * a descriptive error message.
   *
   * ### Usage Example:
   * ```
   * val jwk: Jwk = //...obtain or generate a Jwk
   * try {
   *     Ed25519.validateKey(jwk)
   *     // Key is valid, proceed with further operations...
   * } catch (e: IllegalArgumentException) {
   *     // Handle invalid key...
   * }
   * ```
   *
   * ### Important:
   * Ensure to call this function before using a [Jwk] in cryptographic operations
   * to safeguard against invalid key usage and potential vulnerabilities.
   *
   * @param key The [Jwk] to validate.
   * @throws IllegalArgumentException if the key is not of type [OctetKeyPair].
   */
  private fun validateKey(key: Jwk) {
    require(key.kty == "OKP") { "key must be an Octet Key Pair (kty: OKP)" }
  }
}