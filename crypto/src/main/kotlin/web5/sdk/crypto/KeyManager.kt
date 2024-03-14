package web5.sdk.crypto

import web5.sdk.crypto.jwk.Jwk

/**
 * A key management interface that provides functionality for generating, storing, and utilizing
 * private keys and their associated public keys. Implementations of this interface should handle
 * the secure generation and storage of keys, providing mechanisms for utilizing them in cryptographic
 * operations like signing.
 *
 * Example implementations might provide key management through various Key Management Systems (KMS),
 * such as AWS KMS, Google Cloud KMS, Hardware Security Modules (HSM), or simple in-memory storage,
 * each adhering to the same consistent API for usage within applications.
 */
public interface KeyManager {

  /**
   * Generates and securely stores a private key based on the provided algorithm and options,
   * returning a unique alias that can be utilized to reference the generated key for future operations.
   *
   * @param algorithmId The algorithmId to use for key generation.
   * @param options (Optional) Additional options to control key generation behavior.
   * @return A unique alias (String) that can be used to reference the stored key.
   *
   * Implementations should ensure secure storage of the generated keys, protecting against
   * unauthorized access and ensuring cryptographic strength according to the provided parameters.
   */
  public fun generatePrivateKey(algorithmId: AlgorithmId, options: KeyGenOptions? = null): String

  /**
   * Retrieves the public key associated with a previously stored private key, identified by the provided alias.
   *
   * @param keyAlias The alias referencing the stored private key.
   * @return The associated public key in Jwk (JSON Web Key) format.
   *
   * The function should provide the public key in a format suitable for external sharing and usage,
   * enabling others to perform operations like verifying signatures or encrypting data for the private key holder.
   */
  public fun getPublicKey(keyAlias: String): Jwk

  /**
   * Signs the provided payload using the private key identified by the provided alias.
   *
   * @param keyAlias The alias referencing the stored private key.
   * @param signingInput The data to be signed.
   * @return The signature in JWS R+S format
   *
   * Implementations should ensure that the signing process is secured, utilizing secure cryptographic
   * practices and safeguarding the private key during the operation. The specific signing algorithm
   * used may depend on the type and parameters of the stored key.
   */
  public fun sign(keyAlias: String, signingInput: ByteArray): ByteArray

  /**
   * Return the alias of [publicKey], as was originally returned by [generatePrivateKey].
   *
   * @param publicKey A public key in Jwk (JSON Web Key) format
   * @return The alias belonging to [publicKey]
   * @throws IllegalArgumentException if the key is not known to the [KeyManager]
   */
  public fun getDeterministicAlias(publicKey: Jwk): String
}

/**
 * KeyExporter is an abstraction that can be leveraged to
 * implement types which intend to export keys.
 *
 */
public interface KeyExporter {

  /**
   * ExportKey exports the key specific by the key ID from the KeyManager.
   *
   * @param keyId the keyId whose corresponding key to export
   * @return the Jwk representation of the key
   */
  public fun exportKey(keyId: String): Jwk
}

/**
 * KeyImporter is an abstraction that can be leveraged to
 * implement types which intend to import keys.
 *
 */
public interface KeyImporter {

  /**
   * ImportKey imports the key into the KeyManager
   * and returns the key alias.
   *
   * @param jwk the Jwk representation of the key to import
   * @return the key alias of the imported key
   */
  public fun importKey(jwk: Jwk): String
}