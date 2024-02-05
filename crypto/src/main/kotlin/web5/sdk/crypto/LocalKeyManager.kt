package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK

/**
 * A class for managing cryptographic keys locally.
 *
 * `LocalKeyManager` is an implementation of [KeyManager] that stores keys locally using a mutable map. It provides methods to:
 * - Generate private keys ([generatePrivateKey])
 * - Retrieve public keys ([getPublicKey])
 * - Sign payloads ([sign])
 *
 * ### Example Usage:
 * ```
 * val keyManager = LocalKeyManager()
 * val keyID = keyManager.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
 * val publicKey = keyManager.getPublicKey(keyID)
 * ```
 *
 * ### Notes:
 * - Keys are stored in a local mutable map and will be lost once the application is terminated or the object is garbage-collected.
 * - It is suitable for testing or scenarios where persistent storage of keys is not necessary.
 */
public class LocalKeyManager : KeyManager {

  /**
   * A local keystore represented as a flat key-value map, where the key is a key ID.
   */
  private val keyStore: MutableMap<String, JWK> = HashMap()

  /**
   * Generates a private key using specified algorithm and curve, and stores it in the local keyStore.
   *
   * @param algorithm The JWA algorithm identifier.
   * @param curve The elliptic curve. Null for algorithms that do not use elliptic curves.
   * @param options Options for key generation, may include specific parameters relevant to the algorithm.
   * @return The key ID of the generated private key.
   */
  override fun generatePrivateKey(algorithm: Algorithm, curve: Curve?, options: KeyGenOptions?): String {
    val jwk = Crypto.generatePrivateKey(algorithm, curve, options)
    keyStore[jwk.keyID] = jwk

    return jwk.keyID
  }

  /**
   * Computes and returns a public key corresponding to the private key identified by the provided keyAlias.
   *
   * @param keyAlias The alias (key ID) of the private key stored in the keyStore.
   * @return The computed public key as a JWK object.
   * @throws Exception if a key with the provided alias is not found in the keyStore.
   */
  override fun getPublicKey(keyAlias: String): JWK {
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
   * @param publicKey A public key in JWK (JSON Web Key) format
   * @return The alias belonging to [publicKey]
   * @throws IllegalArgumentException if the key is not known to the [KeyManager]
   */
  override fun getDeterministicAlias(publicKey: JWK): String {
    val kid = publicKey.keyID ?: publicKey.computeThumbprint().toString()
    require(keyStore.containsKey(kid)) {
      "key with alias $kid not found"
    }
    return kid
  }

  private fun getPrivateKey(keyAlias: String) =
    keyStore[keyAlias] ?: throw IllegalArgumentException("key with alias $keyAlias not found")

  /**
   * Imports a list of keys represented as a list of maps and returns a list of key aliases referring to them.
   *
   * @param keySet A list of key representations in map format.
   * @return A list of key aliases belonging to the imported keys.
   */
  public fun import(keySet: Iterable<Map<String, Any>>): List<String> = keySet.map {
    val jwk = JWK.parse(it)
    import(jwk)
  }

  /**
   * Imports a single key and returns the alias that refers to it.
   *
   * @param jwk A JWK object representing the key to be imported.
   * @return The alias belonging to the imported key.
   */
  public fun import(jwk: JWK): String {
    var kid = jwk.keyID
    if (kid.isNullOrEmpty()) {
      kid = jwk.computeThumbprint().toString()
    }
    keyStore.putIfAbsent(kid, jwk)
    return kid
  }

  /**
   * Exports all stored keys as a list of maps.
   *
   * @return A list of key representations in map format.
   */
  public fun export(): List<Map<String, Any>> = keyStore.map { it.value.toJSONObject() }
}
