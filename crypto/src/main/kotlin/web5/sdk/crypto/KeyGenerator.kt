package web5.sdk.crypto

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType

/**
 * `KeyGenOptions` serves as an interface defining options or parameters that influence
 * cryptographic key generation within the [KeyGenerator] interface.
 *
 * The cryptographic key generation process may be influenced by various parameters, such
 * as key size, secure random generation strategies, or specific curve parameters for
 * elliptic curve cryptography. Implementations of `KeyGenOptions` may encapsulate such
 * parameters, providing a structured means to specify them during key generation.
 *
 * Concrete implementations of `KeyGenOptions` should document and validate their specific
 * parameters, ensuring they are appropriate for the intended cryptographic algorithm or
 * method. Developers are encouraged to make use of `KeyGenOptions` to configure their key
 * generation processes to meet their security and performance requirements.
 *
 * ### Example Usage:
 *
 * ```kotlin
 * val keyGenOptions: KeyGenOptions = ...
 * val keyGenerator: KeyGenerator = ...
 * val privateKey: JWK = keyGenerator.generatePrivateKey(keyGenOptions)
 * ```
 *
 * ### Note:
 * While it may not be mandatory to specify key generation options during key generation,
 * implementations must ensure that secure defaults are utilized when options are not provided.
 */
public interface KeyGenOptions

/**
 * The `KeyGenerator` interface provides a blueprint for implementing cryptographic key
 * generation and conversion functionalities for various cryptographic algorithms and key types.
 *
 * Cryptographic keys play a pivotal role in securing communication and data. This interface
 * standardizes the key management operations including key generation, format conversion,
 * and key derivation, ensuring that implementers adhere to a consistent API. In the realm
 * of cryptographic applications, `KeyGenerator` enables developers to instantiate key pairs,
 * convert keys between various formats, and derive public keys from private ones, while
 * abstracting the specifics of the cryptographic algorithm and key type in use.
 *
 * Implementers are expected to provide concrete implementations for various key management
 * activities for specified algorithms (e.g., RSA, EC) and key types (symmetric/asymmetric),
 * and to handle potential exceptions, especially in scenarios such as deriving public keys
 * in symmetric key contexts.
 *
 * ### Example Usage:
 *
 * ```
 * val keyGenerator: KeyGenerator = ...
 * val privateKey: JWK = keyGenerator.generatePrivateKey()
 * val publicKey: JWK = keyGenerator.getPublicKey(privateKey)
 * val privateKeyBytes: ByteArray = keyGenerator.privateKeyToBytes(privateKey)
 * val restoredPrivateKey: JWK = keyGenerator.bytesToPrivateKey(privateKeyBytes)
 * ```
 *
 * ### Note:
 * For symmetric key generators, certain methods like `getPublicKey` or `publicKeyToBytes`
 * may not be applicable and should throw an `UnsupportedOperationException`.
 */
public interface KeyGenerator {
  /**  Indicates the algorithm intended to be used with the key. */
  public val algorithm: Jwa

  /** Indicates the cryptographic algorithm family used with the key. */
  public val keyType: KeyType

  /** Generates a private key. */
  public fun generatePrivateKey(options: KeyGenOptions? = null): JWK

  /**
   * Derives a public key from the private key provided. Applicable for asymmetric Key Generators only.
   * Implementers of symmetric key generators should throw an UnsupportedOperation Exception
   */
  public fun computePublicKey(privateKey: JWK): JWK

  /**
   * Converts a private key to bytes.
   */
  public fun privateKeyToBytes(privateKey: JWK): ByteArray

  /**
   * Converts a public key to bytes. Applicable for asymmetric [KeyGenerator] implementations only.
   * Implementers of symmetric key generators should throw an UnsupportedOperation Exception
   */
  public fun publicKeyToBytes(publicKey: JWK): ByteArray

  /**
   * Converts a private key as bytes into a JWK.
   */
  public fun bytesToPrivateKey(privateKeyBytes: ByteArray): JWK

  /**
   * Converts a public key as bytes into a JWK. Applicable for asymmetric Key Generators only.
   * Implementers of symmetric key generators should throw an UnsupportedOperation Exception
   */
  public fun bytesToPublicKey(publicKeyBytes: ByteArray): JWK
}