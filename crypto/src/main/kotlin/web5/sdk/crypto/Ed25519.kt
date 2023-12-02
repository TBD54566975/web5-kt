package web5.sdk.crypto

import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.subtle.Ed25519Verify
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import web5.sdk.common.Convert
import web5.sdk.crypto.Ed25519.PRIV_MULTICODEC
import web5.sdk.crypto.Ed25519.PUB_MULTICODEC
import web5.sdk.crypto.Ed25519.algorithm
import web5.sdk.crypto.Ed25519.keyType
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
 * @property keyType Specifies the key type. For Ed25519, this is `OKP`.
 * @property PUB_MULTICODEC A byte array representing the multicodec prefix for an Ed25519 public key.
 * @property PRIV_MULTICODEC A byte array representing the multicodec prefix for an Ed25519 private key.
 */

public object Ed25519 : KeyGenerator, Signer {
  override val algorithm: Algorithm = Algorithm.EdDSA
  override val keyType: KeyType = KeyType.OKP

  public const val PUB_MULTICODEC: Int = 0xed
  public const val PRIV_MULTICODEC: Int = 0x1300

  /**
   * Generates a private key utilizing the Ed25519 algorithm.
   *
   * @param options (Optional) Additional options to control the key generation process.
   * @return The generated private key in JWK format.
   */
  override fun generatePrivateKey(options: KeyGenOptions?): JWK {
    return OctetKeyPairGenerator(Curve.Ed25519)
      .algorithm(JWSAlgorithm.EdDSA)
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()
      .toOctetKeyPair()
  }

  /**
   * Derives the public key corresponding to a given private key.
   *
   * @param privateKey The private key in JWK format.
   * @return The corresponding public key in JWK format.
   */
  override fun computePublicKey(privateKey: JWK): JWK {
    require(privateKey is OctetKeyPair) { "private key must be an Octet Key Pair (kty: OKP)" }

    return privateKey.toOctetKeyPair().toPublicJWK()
  }

  override fun privateKeyToBytes(privateKey: JWK): ByteArray {
    validateKey(privateKey)

    return privateKey.toOctetKeyPair().decodedD
  }

  override fun publicKeyToBytes(publicKey: JWK): ByteArray {
    validateKey(publicKey)

    return publicKey.toOctetKeyPair().decodedX
  }

  override fun bytesToPrivateKey(privateKeyBytes: ByteArray): JWK {
    val privateKeyParameters = Ed25519PrivateKeyParameters(privateKeyBytes, 0)
    val publicKeyBytes = privateKeyParameters.generatePublicKey().encoded

    val base64UrlEncodedPrivateKey = Convert(privateKeyBytes).toBase64Url(padding = false)
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url(padding = false)

    return OctetKeyPair.Builder(Curve.Ed25519, Base64URL(base64UrlEncodedPublicKey))
      .algorithm(algorithm.toNimbusdsJWSAlgorithm())
      .keyIDFromThumbprint()
      .d(Base64URL(base64UrlEncodedPrivateKey))
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  override fun bytesToPublicKey(publicKeyBytes: ByteArray): JWK {
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url(padding = false)

    return OctetKeyPair.Builder(Curve.Ed25519, Base64URL(base64UrlEncodedPublicKey))
      .algorithm(algorithm.toNimbusdsJWSAlgorithm())
      .keyIDFromThumbprint()
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  override fun sign(privateKey: JWK, payload: ByteArray, options: SignOptions?): ByteArray {
    validateKey(privateKey)

    val privateKeyBytes = privateKeyToBytes(privateKey)
    val signer = Ed25519Sign(privateKeyBytes)

    return signer.sign(payload)
  }

  override fun verify(publicKey: JWK, signedPayload: ByteArray, signature: ByteArray, options: VerifyOptions?) {
    validateKey(publicKey)

    val publicKeyBytes = publicKeyToBytes(publicKey)
    val verifier = Ed25519Verify(publicKeyBytes)

    try {
      verifier.verify(signature, signedPayload)
    } catch (e: GeneralSecurityException) {
      throw SignatureException(e.message, e)
    }
  }

  /**
   * Validates the provided [JWK] (JSON Web Key) to ensure it conforms to the expected key type and format.
   *
   * This function checks the following:
   * - The key must be an instance of [OctetKeyPair].
   * - The key type (`kty`) must be [KeyType.OKP] (Octet Key Pair).
   *
   * If any of these checks fail, this function throws an [IllegalArgumentException] with
   * a descriptive error message.
   *
   * ### Usage Example:
   * ```
   * val jwk: JWK = //...obtain or generate a JWK
   * try {
   *     Secp256k1.validateKey(jwk)
   *     // Key is valid, proceed with further operations...
   * } catch (e: IllegalArgumentException) {
   *     // Handle invalid key...
   * }
   * ```
   *
   * ### Important:
   * Ensure to call this function before using a [JWK] in cryptographic operations
   * to safeguard against invalid key usage and potential vulnerabilities.
   *
   * @param key The [JWK] to validate.
   * @throws IllegalArgumentException if the key is not of type [OctetKeyPair] or if the key type is not [KeyType.EC].
   */
  public fun validateKey(key: JWK) {
    require(key is OctetKeyPair) { "private key must be an Octet Key Pair (kty: OKP)" }
    require(key.keyType == keyType) { "private key key type must be OKP" }
  }
}