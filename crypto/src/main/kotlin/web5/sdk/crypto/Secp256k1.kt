package web5.sdk.crypto

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.crypto.Secp256k1.PRIV_MULTICODEC
import web5.sdk.crypto.Secp256k1.PUB_MULTICODEC
import web5.sdk.crypto.jwk.Jwk
import java.math.BigInteger
import java.security.MessageDigest
import java.security.Security
import java.security.SignatureException

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
 * - Public and private keys can be encoded with [PUB_MULTICODEC] and [PRIV_MULTICODEC] respectively.
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

  override val algorithm: Jwa = Jwa.ES256K
  override val curve: JwaCurve = JwaCurve.secp256k1
  override val keyType: String = "EC"

  /** [reference](https://github.com/multiformats/multicodec/blob/master/table.csv#L92). */
  public const val PUB_MULTICODEC: Int = 0xe7

  /** [reference](https://github.com/multiformats/multicodec/blob/master/table.csv#L169). */
  public const val PRIV_MULTICODEC: Int = 0x1301

  /**  uncompressed key leading byte. */
  public const val UNCOMPRESSED_KEY_ID: Byte = 0x04

  /** Compressed key leading byte that indicates whether the Y coordinate is even. */
  public const val COMP_KEY_EVEN_Y_ID: Byte = 0x02

  /** Compressed key leading byte that indicates whether the Y coordinate is odd. */
  public const val COMP_KEY_ODD_Y_ID: Byte = 0x03

  /**
   * Size of an uncompressed public key in bytes.
   *
   * The uncompressed key is represented with a leading 0x04 byte,
   * followed by 32 bytes for the X coordinate and 32 bytes for the Y coordinate.
   * Thus, an uncompressed key is 65 bytes in size.
   */
  public const val UNCOMPRESSED_KEY_SIZE: Int = 65

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
  public const val COMPRESSED_KEY_SIZE: Int = 33

  public const val SIG_SIZE: Int = 64

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
   * contains the paramaters of the curve's equation (e.g. n, g etc.)
   */
  private val spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")

  /**
   * another way that parameters of a curve's equation are represented.
   */
  private val curveParams: ECDomainParameters = ECDomainParameters(spec.curve, spec.g, spec.n)

  /**
   * Generates a private key using the SECP256K1 curve and ES256K algorithm.
   *
   * The generated key will have its key ID derived from the thumbprint and will
   * be intended for signature use.
   *
   * @param options Options for key generation (currently unused, provided for possible future expansion).
   * @return A Jwk representing the generated private key.
   */
  override fun generatePrivateKey(options: KeyGenOptions?): Jwk {
    // TODO use tink to generate private key https://github.com/TBD54566975/web5-kt/issues/273
    val privateKey = ECKeyGenerator(Curve.SECP256K1)
      .provider(BouncyCastleProviderSingleton.getInstance())
      .generate()

    val jwk = Jwk.Builder("EC", privateKey.curve.name)
      .privateKey(privateKey.d.toString())
      .x(privateKey.x.toString())
      .y(privateKey.y.toString())
      .build()

    return jwk
  }

  override fun computePublicKey(privateKey: Jwk): Jwk {
    validateKey(privateKey)

    val jwk = Jwk.Builder(privateKey.kty, curve.name)
      .algorithm(algorithm.name)
      .apply {
        privateKey.use?.let { keyUse(it) }
        privateKey.alg?.let { algorithm(it) }
        privateKey.x?.let { x(it) }
        privateKey.y?.let { y(it) }
      }
      .build()

    return jwk
  }

  override fun privateKeyToBytes(privateKey: Jwk): ByteArray {
    validateKey(privateKey)

    return Convert(privateKey.d, EncodingFormat.Base64Url).toByteArray()
  }

  override fun publicKeyToBytes(publicKey: Jwk): ByteArray {
    validateKey(publicKey)

    val xBytes = Convert(publicKey.x, EncodingFormat.Base64Url).toByteArray()
    val yBytes = Convert(publicKey.y, EncodingFormat.Base64Url).toByteArray()

    return byteArrayOf(UNCOMPRESSED_KEY_ID) + xBytes + yBytes
  }

  override fun bytesToPrivateKey(privateKeyBytes: ByteArray): Jwk {
    var pointQ: ECPoint = spec.g.multiply(BigInteger(1, privateKeyBytes))

    pointQ = pointQ.normalize()
    val rawX = pointQ.rawXCoord.encoded
    val rawY = pointQ.rawYCoord.encoded

    return Jwk.Builder("EC", curve.name)
      .algorithm(algorithm.name)
      .x(Convert(rawX).toBase64Url())
      .y(Convert(rawY).toBase64Url())
      .privateKey(Convert(privateKeyBytes).toBase64Url())
      .build()
  }

  override fun bytesToPublicKey(publicKeyBytes: ByteArray): Jwk {
    val xBytes = publicKeyBytes.sliceArray(1..32)
    val yBytes = publicKeyBytes.sliceArray(33..64)

    val jwk = Jwk.Builder("EC", curve.name)
      .algorithm(algorithm.name)
      .x(Convert(xBytes).toBase64Url())
      .y(Convert(yBytes).toBase64Url())
      .build()

    return jwk
  }

  /**
   * Deterministically signs the provided payload using the ECDSA (Elliptic Curve Digital Signature Algorithm)
   * with the curve `secp256k1`.
   *
   * This function is designed to generate deterministic signatures, meaning that signing the
   * same payload with the same private key will always produce the same signature.
   *
   * @param privateKey The private key used for signing, provided as a `Jwk` (JSON Web Key).
   * @param payload The byte array containing the data to be signed.
   *               Ensure that the payload is prepared appropriately, considering any necessary
   *               hashing or formatting relevant to the application's security requirements.
   * @param options Optional parameter to provide additional configuration for the signing process.
   *                Currently unused and may be provided as `null`.
   * @return A byte array representing the signature, generated by concatenating the `r` and `s`
   *         components of the ECDSA signature.
   * @throws IllegalArgumentException If the provided key, payload, or options are invalid or inappropriate
   *                                  for the signing process.
   */
  override fun sign(privateKey: Jwk, payload: ByteArray, options: SignOptions?): ByteArray {
    val privateKeyBigInt = BigInteger(1, Convert(privateKey.d, EncodingFormat.Base64Url).toByteArray())
    val privateKeyParams = ECPrivateKeyParameters(privateKeyBigInt, curveParams)

    // generates k value deterministically using the private key and message hash, ensuring that signing the same
    // message with the same private key will always produce the same signature.
    val kCalculator = HMacDSAKCalculator(SHA256Digest())

    val signer = ECDSASigner(kCalculator)
    signer.init(true, privateKeyParams)

    val sha256 = MessageDigest.getInstance("SHA-256")
    val payloadDigest = sha256.digest(payload)

    val (rBigint, initialSBigint) = signer.generateSignature(payloadDigest)

    // ensure s is always in the bottom half of n.
    // why? - An ECDSA signature for a given message and private key is not strictly unique. Specifically, if
    //      (r,s) is a valid signature, then (r, mod(-s, n)) is also a valid signature. This means there
    //      are two valid signatures for every message/private key pair: one with a "low" s value and one
    //      with a "high" s value. standardizing acceptance of only 1 of the 2 prevents signature malleability
    //      issues. Signature malleability is a notable concern in Bitcoin which introduced the low-s
    //      requirement for all signatures in version 0.11.1.
    // n - a large prime number that defines the maximum number of points that can be created by
    //    adding the base point, G, to itself repeatedly. The base point
    // G - AKA generator point. a predefined point on an elliptic curve.
    // TODO: consider making lowS a boolean option.
    val halfN = curveParams.n.shiftRight(1)
    val sBigint = if (initialSBigint >= halfN) curveParams.n.subtract(initialSBigint) else initialSBigint

    // Secp256k1 signatures are always 64 bytes.
    return rBigint.toFixedByteArray(SIG_SIZE / 2) + sBigint.toFixedByteArray(SIG_SIZE / 2)
  }

  /**
   * Verifies a signature against a given payload using the ECDSA (Elliptic Curve Digital Signature Algorithm)
   * with the curve `secp256k1`. This function supports deterministic k-value generation
   * through HMAC and SHA-256, ensuring consistent verification outcomes for identical payloads
   * and signatures.
   *
   * @param publicKey The public key used for verification, provided as a `Jwk` (JSON Web Key).
   * @param signedPayload The byte array containing the data that was signed.
   * @param signature The byte array representing the signature to be verified against the payload.
   * @param options Optional parameter to provide additional configuration for the verification process.
   * @throws SignatureException If the signature does not validly correspond to the provided payload
   *                            and public key, indicating either a data integrity issue
   * @throws IllegalArgumentException If the provided public key or signature format is invalid or not
   *                                  supported by the implementation.
   */
  override fun verify(publicKey: Jwk, signedPayload: ByteArray, signature: ByteArray, options: VerifyOptions?) {
    val publicKeyBytes = publicKeyToBytes(publicKey)
    val publicKeyPoint = spec.curve.decodePoint(publicKeyBytes)

    val publicKeyParams = ECPublicKeyParameters(publicKeyPoint, curveParams)

    // generates k value deterministically using the private key and message hash, ensuring that signing the same
    // message with the same private key will always produce the same signature.
    val kCalculator = HMacDSAKCalculator(SHA256Digest())
    val signer = ECDSASigner(kCalculator)

    val sha256 = MessageDigest.getInstance("SHA-256")
    val payloadDigest = sha256.digest(signedPayload)

    signer.init(false, publicKeyParams)

    val rBytes = signature.sliceArray(0 until signature.size / 2)
    val sBytes = signature.sliceArray(signature.size / 2 until signature.size)

    val rBigInt = BigInteger(1, rBytes)
    val sBigInt = BigInteger(1, sBytes)

    val result = signer.verifySignature(payloadDigest, rBigInt, sBigInt)

    if (!result) {
      throw SignatureException("Invalid Signature")
    }
  }

  /**
   * Validates the provided [Jwk] (JSON Web Key) to ensure it conforms to the expected key type and format.
   *
   * This function checks the following:
   * - The key must be an instance of [ECKey].
   *
   * If any of these checks fail, this function throws an [IllegalArgumentException] with
   * a descriptive error message.
   *
   * ### Usage Example:
   * ```
   * val jwk: Jwk = //...obtain or generate a Jwk
   * try {
   *     Secp256k1.validateKey(jwk)
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
   * @throws IllegalArgumentException if the key is not of type [ECKey].
   */
  public fun validateKey(key: Jwk) {
    require(key.kty == "EC") { "private key must be an ECKey (kty: EC)" }
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
    require(publicKeyBytes.size == UNCOMPRESSED_KEY_SIZE && publicKeyBytes[0] == UNCOMPRESSED_KEY_ID) {
      "Public key must be 65 bytes long and start with 0x04"
    }

    val xBytes = publicKeyBytes.sliceArray(publicKeyXRange)
    val yBytes = publicKeyBytes.sliceArray(publicKeyYRange)

    val prefix = if (yBytes.last() % 2 == 0) COMP_KEY_EVEN_Y_ID else COMP_KEY_ODD_Y_ID
    return byteArrayOf(prefix) + xBytes
  }

  /**
   * Inflates a compressed public key.
   */
  public fun inflatePublicKey(publicKeyBytes: ByteArray): ByteArray {
    require(publicKeyBytes.size == COMPRESSED_KEY_SIZE) { "Invalid key size" }

    val ecPoint = spec.curve.decodePoint(publicKeyBytes)
    val xBytes = ecPoint.rawXCoord.encoded
    val yBytes = ecPoint.rawYCoord.encoded

    return byteArrayOf(UNCOMPRESSED_KEY_ID) + xBytes + yBytes
  }
}

/**
 * Converts a [BigInteger] to a [ByteArray] of fixed length.
 *
 * This function adjusts the size of the byte array representation of the [BigInteger] to ensure that it is exactly of
 * the expected fixed length. If the original byte array is longer than the expected length, it may be due to a
 * leading 0 byte added by Java to indicate a positive number. This occurs when the most significant bit of the most
 * significant byte is 1. This leading zero byte is added to ensure that the number is interpreted as positive.
 * In this case, the leading 0 byte will be removed.
 *
 *
 * If the original byte array is shorter than the expected length, the function will pad the array with leading 0 bytes
 * to reach the required size.
 *
 * This adjustment is particularly useful when dealing with cryptographic operations where a fixed size byte array
 * is expected, ensuring consistency and correctness of the data format.
 *
 * @param size The expected fixed length of the resulting byte array.
 * @return A [ByteArray] of size [size], representing the [BigInteger] value.
 */
private fun BigInteger.toFixedByteArray(size: Int): ByteArray {
  val variableLengthArray = this.toByteArray()
  val currentSize = variableLengthArray.size

  return when {
    currentSize < size -> ByteArray(size - currentSize) + variableLengthArray
    currentSize > size -> variableLengthArray.takeLast(size).toByteArray()
    else -> variableLengthArray
  }
}