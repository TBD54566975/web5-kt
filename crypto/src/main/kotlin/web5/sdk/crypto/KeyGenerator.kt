package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType

public interface KeyGenOptions

public interface KeyGenerator {
  /**  Indicates the algorithm intended to be used with the key. */
  public val algorithm: Algorithm

  /** Indicates the cryptographic algorithm family used with the key */
  public val keyType: KeyType

  /** Generates a private key */
  public fun generatePrivateKey(options: KeyGenOptions? = null): JWK

  /**
   * Derives a public key from the private key provided. Applicable for asymmetric Key Generators only.
   * Implementers of symmetric key generators should throw an UnsupportedOperation Exception
   */
  public fun getPublicKey(privateKey: JWK): JWK

  /**
   * Converts a private key to bytes
   */
  public fun privateKeyToBytes(privateKey: JWK): ByteArray

  /**
   * Converts a public key to bytes. Applicable for asymmetric Key Generators only.
   * Implementers of symmetric key generators should throw an UnsupportedOperation Exception
   */
  public fun publicKeyToBytes(publicKey: JWK): ByteArray

  /**
   * Converts a private key as bytes into a JWK
   */
  public fun bytesToPrivateKey(privateKeyBytes: ByteArray): JWK

  /**
   * Converts a public key as bytes into a JWK. Applicable for asymmetric Key Generators only.
   * Implementers of symmetric key generators should throw an UnsupportedOperation Exception
   */
  public fun bytesToPublicKey(publicKeyBytes: ByteArray): JWK
}