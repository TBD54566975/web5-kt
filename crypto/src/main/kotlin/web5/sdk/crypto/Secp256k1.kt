package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import web5.sdk.crypto.Secp256k1.privMultiCodec
import web5.sdk.crypto.Secp256k1.pubMulticodec
import java.math.BigInteger
import java.security.Security
import java.security.Signature

/**
 * A cryptographic object responsible for key generation, signature creation, and signature verification
 * utilizing the SECP256K1 elliptic curve, widely used for Bitcoin and Ethereum transactions.
 *
 * The object uses the Nimbus JOSE+JWT library and implements the [KeyGenerator] and [Signer] interfaces,
 * providing specific implementation details for SECP256K1.
 *
 * ### Key Points:
 * - Utilizes the ES256K algorithm for signing JWTs.
 * - Utilizes BouncyCastle as the underlying security provider.
 * - Public and private keys can be encoded with [pubMulticodec] and [privMultiCodec] respectively.
 *
 * ### Example Usage:
 * ```
 * val privateKey = Secp256k1.generatePrivateKey()
 * val publicKey = Secp256k1.getPublicKey(privateKey)
 * ```
 *
 * ### Key Generation and Management:
 * - `generatePrivateKey`: Generates a private key for the SECP256K1 curve.
 * - `getPublicKey`: Derives the corresponding public key from a private key.
 *
 * ### Signing and Verification:
 * - `sign`: Generates a digital signature.
 * - `verify`: Verifies a digital signature.
 *
 *
 * @see KeyGenerator for generating key details.
 * @see Signer for handling signing operations.
 */
public object Secp256k1 : KeyGenerator, Signer {
  init {
    Security.addProvider(BouncyCastleProviderSingleton.getInstance())
  }

  override val algorithm: Algorithm = JWSAlgorithm.ES256K
  override val keyType: KeyType = KeyType.EC

  /** [reference](https://github.com/multiformats/multicodec/blob/master/table.csv#L92). */
  public const val pubMulticodec: Int = 0xe7

  /** [reference](https://github.com/multiformats/multicodec/blob/master/table.csv#L169). */
  public const val privMultiCodec: Int = 0x1301

  /**  uncompressed key leading byte. */
  public const val uncompressedKeyIdentifier: Byte = 0x04

  /** Compressed key leading byte that indicates whether the Y coordinate is even. */
  public const val compressedKeyEvenYIdentifier: Byte = 0x02

  /** Compressed key leading byte that indicates whether the Y coordinate is odd. */
  public const val compressedKeyOddYIdentifier: Byte = 0x03

  /**
   * Size of an uncompressed public key in bytes.
   *
   * The uncompressed key is represented with a leading 0x04 byte,
   * followed by 32 bytes for the X coordinate and 32 bytes for the Y coordinate.
   * Thus, an uncompressed key is 65 bytes in size.
   */
  public const val uncompressedKeySize: Int = 65

  /**
   * The byte size of a compressed public key.
   *
   * A compressed public key in elliptic curve cryptography typically consists of:
   * - A single byte prefix: 0x02 or 0x03, indicating whether the Y coordinate is even or odd, respectively
   * - 32 bytes representing the X coordinate
   * Thus, a compressed public key is 33 bytes in size.
   *
   * Example of use:
   * This constant can be utilized for validating the length of a byte array supposed to
   * represent a compressed public key, ensuring it conforms to the expected format.
   */
  public const val compressedKeySize: Int = 33

  /**
   * Range that defines the position of the X coordinate in an uncompressed public key byte array.
   *
   * The X coordinate is typically found in bytes 1 through 32 (inclusive) in the byte array representation
   * of an uncompressed public key, assuming the first byte is reserved for the prefix (0x04).
   */
  public val publicKeyXRange: IntRange = 1..32

  /**
   * Range that defines the position of the Y coordinate in an uncompressed public key byte array.
   *
   * The Y coordinate is typically found in bytes 33 through 64 (inclusive) in the byte array representation
   * of an uncompressed public key, following the X coordinate.
   */
  public val publicKeyYRange: IntRange = 33..64

  /**
   * Generates a private key using the SECP256K1 curve and ES256K algorithm.
   *
   * The generated key will have its key ID derived from the thumbprint and will
   * be intended for signature use.
   *
   * @param options Options for key generation (currently unused, provided for possible future expansion).
   * @return A JWK representing the generated private key.
   */
  override fun generatePrivateKey(options: KeyGenOptions?): JWK {
    return ECKeyGenerator(Curve.SECP256K1)
      .algorithm(JWSAlgorithm.ES256K)
      .provider(BouncyCastleProviderSingleton.getInstance())
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()
  }

  override fun computePublicKey(privateKey: JWK): JWK {
    validateKey(privateKey)

    return privateKey.toECKey().toPublicJWK()
  }

  override fun privateKeyToBytes(privateKey: JWK): ByteArray {
    validateKey(privateKey)

    return privateKey.toECKey().d.decode()
  }

  override fun publicKeyToBytes(publicKey: JWK): ByteArray {
    validateKey(publicKey)

    val ecKey = publicKey.toECKey()
    val xBytes = ecKey.x.decode()
    val yBytes = ecKey.y.decode()

    return byteArrayOf(uncompressedKeyIdentifier) + xBytes + yBytes
  }

  override fun bytesToPrivateKey(privateKeyBytes: ByteArray): JWK {
    val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
    var pointQ: ECPoint = spec.g.multiply(BigInteger(1, privateKeyBytes))

    pointQ = pointQ.normalize()
    val rawX = pointQ.rawXCoord.encoded
    val rawY = pointQ.rawYCoord.encoded

    return ECKey.Builder(Curve.SECP256K1, Base64URL.encode(rawX), Base64URL.encode(rawY))
      .algorithm(JWSAlgorithm.ES256K)
      .keyIDFromThumbprint()
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  override fun bytesToPublicKey(publicKeyBytes: ByteArray): JWK {
    // require(publicKeyBytes[0] == 0x04.toByte()) { "compressed public keys not supported yet" }

    val xBytes = publicKeyBytes.sliceArray(1..32)
    val yBytes = publicKeyBytes.sliceArray(33..64)

    return ECKey.Builder(Curve.SECP256K1, Base64URL.encode(xBytes), Base64URL.encode(yBytes))
      .algorithm(JWSAlgorithm.ES256K)
      .keyIDFromThumbprint()
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  override fun sign(privateKey: JWK, payload: ByteArray, options: SignOptions?): ByteArray {
    val signature = Signature.getInstance("SHA256withPLAIN-ECDSA", "BC")

    signature.initSign(privateKey.toECKey().toPrivateKey())
    signature.update(payload)

    return signature.sign()
  }

  override fun verify(publicKey: JWK, signedPayload: ByteArray, signature: ByteArray, options: VerifyOptions?) {
    val verifier = Signature.getInstance("SHA256withPLAIN-ECDSA", "BC")

    verifier.initVerify(publicKey.toECKey().toPublicKey())
    verifier.update(signedPayload)

    verifier.verify(signature)
  }

  /**
   * Validates the provided [JWK] (JSON Web Key) to ensure it conforms to the expected key type and format.
   *
   * This function checks the following:
   * - The key must be an instance of [ECKey].
   * - The key type (`kty`) must be [KeyType.EC] (Elliptic Curve).
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
   * @throws IllegalArgumentException if the key is not of type [ECKey] or if the key type is not [KeyType.EC].
   */
  public fun validateKey(key: JWK) {
    require(key is ECKey) { "private key must be an ECKey (kty: EC)" }
    require(key.keyType == keyType) { "private key key type must be EC" }
  }

  /**
   * Compresses a public key represented by its X and Y coordinates concatenated in a single byte array.
   *
   * Assumes the input starts with a leading 0x04 byte, which is commonly used to denote an uncompressed public key
   * in some elliptic curve representations.
   *
   * @param publicKeyBytes A byte array representing the public key, expected to be 65 bytes with the first byte being 0x04.
   *                       The following 32 bytes are for the X coordinate, and the last 32 for the Y coordinate.
   * @return The compressed public key as a byte array.
   * @throws IllegalArgumentException if the input byte array is not of expected length or doesn't start with 0x04.
   */
  public fun compressPublicKey(publicKeyBytes: ByteArray): ByteArray {
    require(publicKeyBytes.size == uncompressedKeySize && publicKeyBytes[0] == uncompressedKeyIdentifier) {
      "Public key must be 65 bytes long and start with 0x04"
    }

    val xBytes = publicKeyBytes.sliceArray(publicKeyXRange)
    val yBytes = publicKeyBytes.sliceArray(publicKeyYRange)

    val prefix = if (yBytes.last() % 2 == 0) compressedKeyEvenYIdentifier else compressedKeyOddYIdentifier
    return byteArrayOf(prefix) + xBytes
  }

  /**
   * Inflates a compressed public key.
   */
  public fun inflatePublicKey(publicKeyBytes: ByteArray): ByteArray {
    require(publicKeyBytes.size == compressedKeySize) { "Invalid key size" }

    val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val curve = spec.curve

    val ecPoint = curve.decodePoint(publicKeyBytes)
    val xBytes = ecPoint.rawXCoord.encoded
    val yBytes = ecPoint.rawYCoord.encoded

    return byteArrayOf(uncompressedKeyIdentifier) + xBytes + yBytes
  }

}