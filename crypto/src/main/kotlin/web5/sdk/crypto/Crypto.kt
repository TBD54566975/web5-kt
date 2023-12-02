package web5.sdk.crypto

import com.nimbusds.jose.jwk.JWK
import web5.sdk.crypto.Crypto.generatePrivateKey
import web5.sdk.crypto.Crypto.publicKeyToBytes
import web5.sdk.crypto.Crypto.sign

public typealias CryptoAlgorithm = Pair<Algorithm?, Curve?>

/**
 * Cryptography utility object providing key generation, signature creation, and other crypto-related functionalities.
 *
 * The `Crypto` object operates based on provided algorithms and curve types, facilitating a generic
 * approach to handling multiple cryptographic algorithms and their respective key types.
 * It offers convenience methods to:
 * - Generate private keys ([generatePrivateKey])
 * - Create digital signatures ([sign])
 * - conversion from JWK <-> bytes ([publicKeyToBytes])
 * - Get relevant key generators and signers based on algorithm and curve type.
 *
 * Internally, it utilizes predefined mappings to pair algorithms and curve types with their respective [KeyGenerator]
 * and [Signer] implementations, ensuring appropriate handlers are utilized for different cryptographic approaches.
 * It also includes mappings to manage multicodec functionality, providing a mapping between byte arrays and
 * respective key generators.
 *
 * ### Example Usage:
 * ```
 * val privateKey: JWK = Crypto.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
 * ```
 *
 * ### Key Points:
 * - Manages key generation and signing operations via predefined mappings to handle different crypto approaches.
 * - Provides mechanisms to perform actions (e.g., signing, key generation) dynamically based on algorithm and curve.
 *
 * @see KeyGenerator for key generation functionalities.
 * @see Signer for signing functionalities.
 */
public object Crypto {
  private val keyGenerators = mapOf<CryptoAlgorithm, KeyGenerator>(
    Pair(null, Curve.SECP256K1) to Secp256k1,
    Pair(Secp256k1.algorithm, null) to Secp256k1,
    Pair(Secp256k1.algorithm, Curve.SECP256K1) to Secp256k1,
    Pair(Ed25519.algorithm, Curve.Ed25519) to Ed25519
  )

  private val keyGeneratorsByMultiCodec = mapOf<Int, KeyGenerator>(
    Ed25519.PRIV_MULTICODEC to Ed25519,
    Ed25519.PUB_MULTICODEC to Ed25519,
    Secp256k1.PRIV_MULTICODEC to Secp256k1,
    Secp256k1.PUB_MULTICODEC to Secp256k1
  )

  private val multiCodecsByAlgorithm = mapOf(
    Pair(Secp256k1.algorithm, null) to Secp256k1.PUB_MULTICODEC,
    Pair(Secp256k1.algorithm, Curve.SECP256K1) to Secp256k1.PUB_MULTICODEC,
    Pair(Ed25519.algorithm, Curve.Ed25519) to Ed25519.PUB_MULTICODEC
  )

  private val signers = mapOf<CryptoAlgorithm, Signer>(
    Pair(null, Curve.SECP256K1) to Secp256k1,
    Pair(Secp256k1.algorithm, null) to Secp256k1,
    Pair(Secp256k1.algorithm, Curve.SECP256K1) to Secp256k1,
    Pair(Ed25519.algorithm, Curve.Ed25519) to Ed25519
  )

  /**
   * Generates a private key using the specified algorithm and curve, utilizing the appropriate [KeyGenerator].
   *
   * @param algorithm The JWA algorithm identifier.
   * @param curve The elliptic curve. Null for algorithms that do not use elliptic curves.
   * @param options Options for key generation, may include specific parameters relevant to the algorithm.
   * @return The generated private key as a JWK object.
   * @throws IllegalArgumentException if the provided algorithm or curve is not supported.
   */
  public fun generatePrivateKey(algorithm: Algorithm, curve: Curve? = null, options: KeyGenOptions? = null): JWK {
    val keyGenerator = getKeyGenerator(algorithm, curve)
    return keyGenerator.generatePrivateKey(options)
  }

  /**
   * Computes a public key from the given private key, utilizing relevant [KeyGenerator].
   *
   * @param privateKey The private key used to compute the public key.
   * @return The computed public key as a JWK object.
   */
  public fun computePublicKey(privateKey: JWK): JWK {
    val rawCurve = privateKey.toJSONObject()["crv"]
    val curve = rawCurve?.let { Curve.parse(it.toString()) }
    val generator = getKeyGenerator(privateKey.algorithm?.name?.let { Algorithm.valueOf(it) }, curve)

    return generator.computePublicKey(privateKey)
  }

  /**
   * Signs a payload using a private key.
   *
   * This function utilizes the appropriate [Signer] to generate a digital signature
   * of the provided payload using the provided private key.
   *
   * @param privateKey The JWK private key to be used for generating the signature.
   * @param payload The byte array data to be signed.
   * @param options Options for the signing operation, may include specific parameters relevant to the algorithm.
   * @return The digital signature as a byte array.
   */
  public fun sign(privateKey: JWK, payload: ByteArray, options: SignOptions? = null): ByteArray {
    val rawCurve = privateKey.toJSONObject()["crv"]
    val curve = rawCurve?.let { Curve.parse(it.toString()) }

    val signer = getSigner(privateKey.algorithm.toWeb5Algorithm(), curve)

    return signer.sign(privateKey, payload, options)
  }

  /**
   * Verifies a signature against a signed payload using a public key.
   *
   * This function utilizes the relevant verifier, determined by the algorithm and curve
   * used in the JWK, to ensure the provided signature is valid for the signed payload
   * using the provided public key. The algorithm used can either be specified in the
   * public key JWK or passed explicitly as a parameter. If it is not found in either,
   * an exception will be thrown.
   *
   * ## Note
   * Algorithm **MUST** either be present on the [JWK] or be provided explicitly
   *
   * @param publicKey The JWK public key to be used for verifying the signature.
   * @param signedPayload The byte array data that was signed.
   * @param signature The signature that will be verified.
   * @param algorithm Optional parameter: the algorithm used for signing/verification,
   *                  if not provided in the JWK. Default is null.
   *
   * @throws IllegalArgumentException if neither the JWK nor the explicit parameter
   *                                  provides an algorithm.
   *
   */
  public fun verify(publicKey: JWK, signedPayload: ByteArray, signature: ByteArray, algorithm: Algorithm? = null) {
    val alg = publicKey.algorithm.toWeb5Algorithm() ?: algorithm
    ?: throw IllegalArgumentException("Algorithm must either be set on JWK or provided explicitly.")

    val curve = getJwkCurve(publicKey)
    val verifier = getVerifier(alg, curve)

    verifier.verify(publicKey, signedPayload, signature)
  }


  /**
   * Converts a [JWK] public key into its byte array representation.
   *
   * @param publicKey A [JWK] object representing the public key to be converted.
   * @return A [ByteArray] representing the byte-level information of the provided public key.
   *
   * ### Example
   * ```kotlin
   * val publicKeyBytes = publicKeyToBytes(myJwkPublicKey)
   * ```
   *
   * ### Note
   * This function assumes that the provided [JWK] contains valid curve and algorithm
   * information. Malformed or invalid [JWK] objects may result in exceptions or
   * unexpected behavior.
   *
   * ### Throws
   * - [IllegalArgumentException] If the algorithm or curve in [JWK] is not supported or invalid.
   */
  public fun publicKeyToBytes(publicKey: JWK): ByteArray {
    val curve = getJwkCurve(publicKey)
    val generator = getKeyGenerator(publicKey.algorithm.toWeb5Algorithm(), curve)

    return generator.publicKeyToBytes(publicKey)
  }

  /**
   * Retrieves a [KeyGenerator] based on the provided algorithm and curve.
   *
   * This function looks up and retrieves the relevant [KeyGenerator] based on the provided
   * algorithm and curve parameters.
   *
   * @param algorithm The cryptographic algorithm to find a key generator for.
   * @param curve The cryptographic curve to find a key generator for.
   * @return The corresponding [KeyGenerator].
   * @throws IllegalArgumentException if the algorithm or curve is not supported.
   */
  public fun getKeyGenerator(algorithm: Algorithm?, curve: Curve? = null): KeyGenerator {
    return keyGenerators.getOrElse(Pair(algorithm, curve)) {
      throw IllegalArgumentException("Algorithm $algorithm not supported")
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
   * Retrieves a [Signer] based on the provided algorithm and curve.
   *
   * This function looks up and retrieves the relevant [Signer] based on the provided
   * algorithm and curve parameters.
   *
   * @param algorithm The cryptographic algorithm to find a signer for.
   * @param curve The cryptographic curve to find a signer for.
   * @return The corresponding [Signer].
   * @throws IllegalArgumentException if the algorithm or curve is not supported.
   */
  public fun getSigner(algorithm: Algorithm?, curve: Curve? = null): Signer {
    return signers.getOrElse(Pair(algorithm, curve)) {
      throw IllegalArgumentException("Algorithm $algorithm not supported")
    }
  }

  /**
   * Retrieves a [Signer] to be used for verification based on the provided algorithm and curve.
   *
   * This function fetches the appropriate [Signer], which contains the verification
   * logic for the cryptographic approach determined by the specified algorithm and curve.
   *
   * @param algorithm The cryptographic algorithm to find a verifier for.
   * @param curve The cryptographic curve to find a verifier for.
   * @return The corresponding [Signer] capable of verification.
   * @throws IllegalArgumentException if the algorithm or curve is not supported.
   */
  public fun getVerifier(algorithm: Algorithm, curve: Curve? = null): Signer {
    return getSigner(algorithm, curve)
  }

  /**
   * Extracts the cryptographic curve information from a [JWK] object.
   *
   * This function parses and returns the curve type used in a JWK.
   * May return `null` if the curve information is not present or unsupported.
   *
   * @param jwk The JWK object from which to extract curve information.
   * @return The [Curve] used in the JWK, or `null` if the curve is not defined or recognized.
   */
  public fun getJwkCurve(jwk: JWK): Curve? {
    val rawCurve = jwk.toJSONObject()["crv"]

    return rawCurve?.let { Curve.parse(it.toString()) }
  }

  /**
   * Retrieves the multicodec identifier associated with a given cryptographic algorithm and curve.
   *
   * This function consults a predefined mapping of cryptographic algorithm and curve pairs to their
   * respective multicodec identifiers, returning the matched identifier.
   * Multicodec identifiers are useful for encoding the format or type of the key in systems that
   * leverage multiple cryptographic standards.
   *
   * @param algorithm The cryptographic [Algorithm] for which the multicodec is requested.
   * @param curve The cryptographic [Curve] associated with the algorithm, or null if not applicable.
   * @return The multicodec identifier as an [Int] if a mapping exists, or null if the algorithm and curve
   *         combination is not supported or mapped.
   *
   * ### Example
   * ```kotlin
   * val multicodec = getAlgorithmMultiCodec(JWSAlgorithm.EdDSA, Curve.Ed25519)
   * ```
   */
  public fun getAlgorithmMultiCodec(algorithm: Algorithm, curve: Curve?): Int? {
    return multiCodecsByAlgorithm[Pair(algorithm, curve)]
  }
}

/**
 * Converts an [Algorithm] from the nimbusds library to a [Algorithm].
 */
public fun com.nimbusds.jose.Algorithm?.toWeb5Algorithm(): Algorithm? {
  return this?.name?.let { Algorithm.valueOf(it) }
}
