package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse

public typealias PrivateKeyJwk = JWK
public typealias PublicKeyJwk = JWK

public interface GenerateOptions

// TODO: add `sign` function signature. add SignOptions interface
// TODO: add `verify` function signature. add VerifyOptions interface
// TODO: add getPublicKey(options)
// TODO: add getPublicKeyJwk(options)

/**
 * interface that is concretely implemented for each cryptographic primitive we intend to support
 * (e.g. [Ed25519] and [Secp256k1]). Includes functions for:
 * * key generation (public & private) as [ByteArray]s and [JWK]s ([ByteArray] often needed for DID creation)
 * * signing
 * * verifying
 * * conversion between [ByteArray] keys <-> [JWK] representation and vice versa
 *
 * This interface includes [generatePrivateKey] and [generatePrivateKeyJwk] functions that take no args.
 * the purpose of the no argument functions are to encourage each concrete implementation to provide
 * a way to generate keys without having to think or know about what options might exist.
 *
 * concrete implementations of these functions can use sensible defaults to call [generatePrivateKey] or
 * [generatePrivateKeyJwk] respectively
 */
public interface CryptoPrimitive<out T : JWK> {
  /**
   * the algorithm this crypto primitive falls under
   */
  public val algorithm: Algorithm

  /**
   * the curve this crypto primitive falls under
   */
  public val curve: Curve

  /**
   * identifies the cryptographic algorithm family that this crypto primitive falls under
   */
  public val keyType: KeyType

  /**
   * identifies the intended use of this crypto primitive
   */
  public val keyUse: KeyUse

  public fun generatePrivateKey(): ByteArray

  public fun generatePrivateKey(options: GenerateOptions): ByteArray

  public fun getPublicKey(privateKeyBytes: ByteArray): ByteArray

  public fun generatePrivateKeyJwk(): T

  public fun generatePrivateKeyJwk(options: GenerateOptions): T

  public fun getPublicKeyJwk(privateKeyJwk: PrivateKeyJwk): JWK

  public fun privateKeyToJwk(privateKeyBytes: ByteArray): T

  public fun publicKeyToJwk(publicKeyBytes: ByteArray): JWK

  public fun publicKeyJwkToBytes(jwk: JWK): ByteArray
}