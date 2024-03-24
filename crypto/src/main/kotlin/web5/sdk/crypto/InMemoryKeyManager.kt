package web5.sdk.crypto

import web5.sdk.common.Json
import web5.sdk.common.Json.toMap
import web5.sdk.crypto.jwk.Jwk

/**
 * A class for managing cryptographic keys in-memory.
 *
 * `InMemoryKeyManager` is an implementation of [KeyManager] that stores keys in-memory using a mutable map. It provides methods to:
 * - Generate private keys ([generatePrivateKey])
 * - Retrieve public keys ([getPublicKey])
 * - Sign payloads ([sign])
 *
 * ### Example Usage:
 * ```
 * val keyManager = InMemoryKeyManager()
 * val keyID = keyManager.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
 * val publicKey = keyManager.getPublicKey(keyID)
 * ```
 *
 * ### Notes:
 * - Keys are stored in an in-memory mutable map and will be lost once the application is terminated or the object is garbage-collected.
 * - It is suitable for testing or scenarios where persistent storage of keys is not necessary.
 */
public class InMemoryKeyManager : KeyManager, KeyExporter, KeyImporter {

  /**
   * An in-memory keystore represented as a flat key-value map, where the key is a key ID.
   */
  private val keyStore: MutableMap<String, Jwk> = HashMap()

  /**
   * Generates a private key using specified algorithmId, and stores it in the in-memory keyStore.
   *
   * @param algorithmId The algorithmId [AlgorithmId].
   * @param options Options for key generation, may include specific parameters relevant to the algorithm.
   * @return The key ID of the generated private key.
   */
  override fun generatePrivateKey(algorithmId: AlgorithmId, options: KeyGenOptions?): String {
    val jwk = Crypto.generatePrivateKey(algorithmId, options)
    if (jwk.kid.isNullOrEmpty()) {
      jwk.kid = jwk.computeThumbprint()
    }

    keyStore[jwk.kid!!] = jwk
    return jwk.kid!!
  }

  /**
   * Computes and returns a public key corresponding to the private key identified by the provided keyAlias.
   *
   * @param keyAlias The alias (key ID) of the private key stored in the keyStore.
   * @return The computed public key as a Jwk object.
   * @throws Exception if a key with the provided alias is not found in the keyStore.
   */
  override fun getPublicKey(keyAlias: String): Jwk {
    // TODO: decide whether to return null or throw an exception
    val privateKey = getPrivateKey(keyAlias)
    return Crypto.computePublicKey(privateKey)
  }

  /**
   * Signs a payload using the private key identified by the provided keyAlias.
   *
   * The implementation of this method is not yet provided and invoking it will throw a [NotImplementedError].
   *
   * @param keyAlias The alias (key ID) of the private key stored in the keyStore.
   * @param signingInput The data to be signed.
   * @return The signature in JWS R+S format
   */
  override fun sign(keyAlias: String, signingInput: ByteArray): ByteArray {
    val privateKey = getPrivateKey(keyAlias)
    return Crypto.sign(privateKey, signingInput)
  }

  /**
   * Return the alias of [publicKey], as was originally returned by [generatePrivateKey].
   *
   * @param publicKey A public key in Jwk (JSON Web Key) format
   * @return The alias belonging to [publicKey]
   * @throws IllegalArgumentException if the key is not known to the [KeyManager]
   */
  override fun getDeterministicAlias(publicKey: Jwk): String {
    val kid = publicKey.computeThumbprint()
    require(keyStore.containsKey(kid)) {
      "key with alias $kid not found"
    }
    return kid
  }

  private fun getPrivateKey(keyAlias: String) =
    keyStore[keyAlias] ?: throw IllegalArgumentException("key with alias $keyAlias not found")

  override fun exportKey(keyId: String): Jwk {
    return this.getPrivateKey(keyId)
  }

  override fun importKey(jwk: Jwk): String {
    val keyAlias = jwk.computeThumbprint()
    keyStore[keyAlias] = jwk
    return keyAlias
  }

}
