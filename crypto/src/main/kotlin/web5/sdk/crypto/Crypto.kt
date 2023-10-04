package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import web5.sdk.crypto.Crypto.generatePrivateKey
import web5.sdk.crypto.Crypto.getPublicKeyBytes
import web5.sdk.crypto.Crypto.sign

/**
 * Cryptography utility object providing key generation, signature creation, and other crypto-related functionalities.
 *
 * The `Crypto` object operates based on provided algorithms and curve types, facilitating a generic
 * approach to handling multiple cryptographic algorithms and their respective key types.
 * It offers convenience methods to:
 * - Generate private keys ([generatePrivateKey])
 * - Create digital signatures ([sign])
 * - Retrieve public key bytes ([getPublicKeyBytes])
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
  private val keyGenerators = mapOf<Algorithm, Map<Curve?, KeyGenerator>>(
    JWSAlgorithm.EdDSA to mapOf(
      Curve.Ed25519 to Ed25519
    ),
    JWSAlgorithm.ES256K to mapOf<Curve?, KeyGenerator>(
      Curve.SECP256K1 to Secp256k1
    )
  )

  private val keyGeneratorsByMultiCodec = mapOf<ByteArray, KeyGenerator>(
    Ed25519.privMultiCodec to Ed25519,
    Ed25519.pubMulticodec to Ed25519,
    Secp256k1.privMultiCodec to Secp256k1,
    Secp256k1.pubMulticodec to Secp256k1
  )

  private val multiCodecsByAlgorithm = mapOf(
    JWSAlgorithm.EdDSA to mapOf(
      Curve.Ed25519 to Ed25519.pubMulticodec
    ),
    JWSAlgorithm.ES256K to mapOf(
      Curve.SECP256K1 to Secp256k1.pubMulticodec
    )
  )

  private val signers = mapOf<Algorithm, Map<Curve?, Signer>>(
    JWSAlgorithm.EdDSA to mapOf(
      Curve.Ed25519 to Ed25519
    ),
    JWSAlgorithm.ES256K to mapOf(
      Curve.SECP256K1 to Secp256k1
    )
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
   * Signs a payload using the specified private key and options.
   *
   * @param privateKey The JWK private key used for signing.
   * @param payload The payload to be signed.
   * @param options Options for the signing process, possibly including additional metadata or specifications.
   * @throws IllegalArgumentException if the curve or algorithm of the private key is not supported.
   */
  public fun sign(privateKey: JWK, payload: Payload, options: SignOptions) {
    val rawCurve = privateKey.toJSONObject()["crv"]
    val curve = rawCurve?.let { Curve.parse(it.toString()) }


    val signer = getSigner(privateKey.algorithm, curve)

    signer.sign(privateKey, payload, options)
  }

  /**
   * Verifies the JSON Web Signature (JWS) using the provided public key.
   *
   * @param publicKey The JSON Web Key (JWK) containing the public key used for verification.
   * @param jws The JSON Web Signature string to verify.
   *
   */
  public fun verify(publicKey: JWK, jws: String) {
    val rawCurve = publicKey.toJSONObject()["crv"]
    val curve = rawCurve?.let { Curve.parse(it.toString()) }


    val verifier = getSigner(publicKey.algorithm, curve)
    verifier.verify(publicKey, jws)
  }

  public fun getPublicKeyBytes(publicKey: JWK): ByteArray {
    val rawCurve = publicKey.toJSONObject()["crv"]
    val curve = rawCurve?.let { Curve.parse(it.toString()) }
    val generator = getKeyGenerator(publicKey.algorithm, curve)

    return generator.publicKeyToBytes(publicKey)
  }

  public fun getKeyGenerator(algorithm: Algorithm, curve: Curve? = null): KeyGenerator {
    val keyGenAlgorithm = keyGenerators.getOrElse(algorithm) {
      throw IllegalArgumentException("Algorithm $algorithm not supported")
    }

    val keyGenerator = keyGenAlgorithm.getOrElse(curve) {
      throw IllegalArgumentException("Curve $curve not supported")
    }

    return keyGenerator
  }

  public fun getKeyGenerator(multiCodec: ByteArray): KeyGenerator {
    return keyGeneratorsByMultiCodec.getOrElse(multiCodec) {
      throw IllegalArgumentException("multicodec not supported")
    }
  }

  public fun getSigner(algorithm: Algorithm, curve: Curve? = null): Signer {
    val signerAlgorithm = signers.getOrElse(algorithm) {
      throw IllegalArgumentException("Algorithm $algorithm not supported")
    }

    val signer = signerAlgorithm.getOrElse(curve) {
      throw IllegalArgumentException("Curve $curve not supported")
    }

    return signer
  }
}