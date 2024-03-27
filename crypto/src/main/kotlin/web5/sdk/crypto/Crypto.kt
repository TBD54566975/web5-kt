package web5.sdk.crypto

import web5.sdk.crypto.Crypto.generatePrivateKey
import web5.sdk.crypto.Crypto.publicKeyToBytes
import web5.sdk.crypto.Crypto.sign
import web5.sdk.crypto.jwk.Jwk

/**
 * Cryptography utility object providing key generation, signature creation, and other crypto-related functionalities.
 *
 * The `Crypto` object operates based on provided algorithms and curve types, facilitating a generic
 * approach to handling multiple cryptographic algorithms and their respective key types.
 * It offers convenience methods to:
 * - Generate private keys ([generatePrivateKey])
 * - Create digital signatures ([sign])
 * - conversion from Jwk <-> bytes ([publicKeyToBytes])
 * - Get relevant key generators and signers based on algorithmId.
 *
 * Internally, it utilizes predefined mappings to pair algorithms and curve types with their respective [KeyGenerator]
 * and [Signer] implementations, ensuring appropriate handlers are utilized for different cryptographic approaches.
 * It also includes mappings to manage multicodec functionality, providing a mapping between byte arrays and
 * respective key generators.
 *
 * ### Example Usage:
 * ```
 * val privateKey: Jwk = Crypto.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
 * ```
 *
 * ### Key Points:
 * - Manages key generation and signing operations via predefined mappings to handle different crypto approaches.
 * - Provides mechanisms to perform actions (e.g., signing, key generation) dynamically based on algorithmId [AlgorithmId].
 *
 * @see KeyGenerator for key generation functionalities.
 * @see Signer for signing functionalities.
 */
public object Crypto {
  private val keyGeneratorsByAlgorithmId = mapOf<AlgorithmId, KeyGenerator>(
    AlgorithmId.secp256k1 to Secp256k1,
    AlgorithmId.Ed25519 to Ed25519
  )

  private val keyGeneratorsByMultiCodec = mapOf<Int, KeyGenerator>(
    Ed25519.PRIV_MULTICODEC to Ed25519,
    Ed25519.PUB_MULTICODEC to Ed25519,
    Secp256k1.PRIV_MULTICODEC to Secp256k1,
    Secp256k1.PUB_MULTICODEC to Secp256k1
  )

  private val multiCodecsByAlgorithmId = mapOf(
    AlgorithmId.secp256k1 to Secp256k1.PUB_MULTICODEC,
    AlgorithmId.Ed25519 to Ed25519.PUB_MULTICODEC
  )

  private val signersByAlgorithmId = mapOf<AlgorithmId, Signer>(
    AlgorithmId.secp256k1 to Secp256k1,
    AlgorithmId.Ed25519 to Ed25519
  )

  /**
   * Generates a private key using the specified algorithmId, utilizing the appropriate [KeyGenerator].
   *
   * @param algorithmId The algorithmId [AlgorithmId].
   * @param options Options for key generation, may include specific parameters relevant to the algorithm.
   * @return The generated private key as a Jwk object.
   * @throws IllegalArgumentException if the provided algorithm or curve is not supported.
   */
  @JvmOverloads
  public fun generatePrivateKey(algorithmId: AlgorithmId, options: KeyGenOptions? = null): Jwk {
    val keyGenerator = getKeyGenerator(algorithmId)
    return keyGenerator.generatePrivateKey(options)
  }

  /**
   * Computes a public key from the given private key, utilizing relevant [KeyGenerator].
   *
   * @param privateKey The private key used to compute the public key.
   * @return The computed public key as a Jwk object.
   */
  public fun computePublicKey(privateKey: Jwk): Jwk {
    val rawCurve = privateKey.crv
    val curve = JwaCurve.parse(rawCurve)
    val generator = getKeyGenerator(AlgorithmId.from(curve))

    return generator.computePublicKey(privateKey)
  }

  /**
   * Signs a payload using a private key.
   *
   * This function utilizes the appropriate [Signer] to generate a digital signature
   * of the provided payload using the provided private key.
   *
   * @param privateKey The Jwk private key to be used for generating the signature.
   * @param payload The byte array data to be signed.
   * @param options Options for the signing operation, may include specific parameters relevant to the algorithm.
   * @return The digital signature as a byte array.
   */
  @JvmOverloads
  public fun sign(privateKey: Jwk, payload: ByteArray, options: SignOptions? = null): ByteArray {
    val curve = getJwkCurve(privateKey)

    val signer = getSigner(AlgorithmId.from(curve))

    return signer.sign(privateKey, payload, options)
  }

  /**
   * Verifies a signature against a signed payload using a public key.
   *
   * This function utilizes the relevant verifier, determined by the algorithm and curve
   * used in the Jwk, to ensure the provided signature is valid for the signed payload
   * using the provided public key. The algorithm used can either be specified in the
   * public key Jwk or passed explicitly as a parameter. If it is not found in either,
   * an exception will be thrown.
   *
   * ## Note
   * Algorithm **MUST** either be present on the [Jwk] or be provided explicitly
   *
   * @param publicKey The Jwk public key to be used for verifying the signature.
   * @param signedPayload The byte array data that was signed.
   * @param signature The signature that will be verified.
   *                  if not provided in the Jwk. Default is null.
   *
   * @throws IllegalArgumentException if neither the Jwk nor the explicit algorithm parameter
   *                                  provides an algorithm.
   *
   */
  public fun verify(publicKey: Jwk, signedPayload: ByteArray, signature: ByteArray) {
    val curve = getJwkCurve(publicKey)
    val verifier = getVerifier(curve)

    verifier.verify(publicKey, signedPayload, signature)
  }


  /**
   * Converts a [Jwk] public key into its byte array representation.
   *
   * @param publicKey A [Jwk] object representing the public key to be converted.
   * @return A [ByteArray] representing the byte-level information of the provided public key.
   *
   * ### Example
   * ```kotlin
   * val publicKeyBytes = publicKeyToBytes(myJwkPublicKey)
   * ```
   *
   * ### Note
   * This function assumes that the provided [Jwk] contains valid curve and algorithm
   * information. Malformed or invalid [Jwk] objects may result in exceptions or
   * unexpected behavior.
   *
   * ### Throws
   * - [IllegalArgumentException] If the algorithm or curve in [Jwk] is not supported or invalid.
   */
  public fun publicKeyToBytes(publicKey: Jwk): ByteArray {
    val curve = getJwkCurve(publicKey)
    val generator = getKeyGenerator(AlgorithmId.from(curve))

    return generator.publicKeyToBytes(publicKey)
  }

  /**
   * Retrieves a [KeyGenerator] based on the provided algorithmId.
   * Currently, we provide key generators for keys that use ECC (see [AlgorithmId] enum)
   *
   * This function looks up and retrieves the relevant [KeyGenerator] based on the provided
   * algorithmId.
   *
   * @param algorithmId The cryptographic algorithmId to find a key generator for.
   * @return The corresponding [KeyGenerator].
   * @throws IllegalArgumentException if the algorithm or curve is not supported.
   */
  public fun getKeyGenerator(algorithmId: AlgorithmId): KeyGenerator {
    return keyGeneratorsByAlgorithmId.getOrElse(algorithmId) {
      throw IllegalArgumentException("Algorithm ${algorithmId.algorithmName} not supported")
    }
  }

  /**
   * Retrieves a [KeyGenerator] based on the provided multicodec identifier.
   *
   * This function looks up and retrieves the relevant [KeyGenerator] based on the provided
   * multicodec identifier.
   *
   * @param multiCodec The multicodec identifier to find a key generator for.
   * @return The corresponding [KeyGenerator].
   * @throws IllegalArgumentException if the multicodec is not supported.
   */
  public fun getKeyGenerator(multiCodec: Int): KeyGenerator {
    return keyGeneratorsByMultiCodec.getOrElse(multiCodec) {
      throw IllegalArgumentException("multicodec not supported")
    }
  }

  /**
   * Retrieves a [Signer] based on the provided algorithmId.
   *
   * This function looks up and retrieves the relevant [Signer]
   * based on the provided algorithmId.
   *
   * @param algorithmId The algorithmId to find a signer for.
   * @return The corresponding [Signer].
   * @throws IllegalArgumentException if the algorithm or curve is not supported.
   */
  public fun getSigner(algorithmId: AlgorithmId): Signer {
    return signersByAlgorithmId.getOrElse(algorithmId) {
      throw IllegalArgumentException("Algorithm ${algorithmId.algorithmName} not supported")
    }
  }

  /**
   * Retrieves a [Signer] to be used for verification based on the provided algorithm and curve.
   *
   * This function fetches the appropriate [Signer], which contains the verification
   * logic for the cryptographic approach determined by the specified algorithm and curve.
   *
   * @param curve The cryptographic curve to find a verifier for.
   * @return The corresponding [Signer] capable of verification.
   * @throws IllegalArgumentException if the algorithm or curve is not supported.
   */
  @JvmOverloads
  public fun getVerifier(curve: JwaCurve? = null): Signer {
    val algorithmId = AlgorithmId.from(curve)
    return getSigner(algorithmId)
  }

  /**
   * Extracts the cryptographic curve information from a [Jwk] object.
   *
   * This function parses and returns the curve type used in a Jwk.
   * May return `null` if the curve information is not present or unsupported.
   *
   * @param jwk The Jwk object from which to extract curve information.
   * @return The [JwaCurve] used in the Jwk, or `null` if the curve is not defined or recognized.
   */
  public fun getJwkCurve(jwk: Jwk): JwaCurve? {
    return JwaCurve.parse(jwk.crv)
  }

  /**
   * Retrieves the multicodec identifier associated with a given algorithmId.
   *
   * This function consults a predefined mapping of algorithmId to their
   * respective multicodec identifiers, returning the matched identifier.
   * Multicodec identifiers are useful for encoding the format or type of the key in systems that
   * leverage multiple cryptographic standards.
   *
   * @param algorithmId The algorithmId for which the multicodec is requested.
   * @return The multicodec identifier as an [Int] if a mapping exists, or null if the algorithmId
   *         combination is not supported or mapped.
   *
   * ### Example
   * ```kotlin
   * val multicodec = getAlgorithmMultiCodec(JWSAlgorithm.EdDSA, Curve.Ed25519)
   * ```
   */
  public fun getAlgorithmMultiCodec(algorithmId: AlgorithmId): Int? {
    return multiCodecsByAlgorithmId[algorithmId]
  }
}