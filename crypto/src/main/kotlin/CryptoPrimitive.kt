package web5.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse

typealias PrivateKeyJwk = JWK
typealias PublicKeyJwk = JWK

interface GenerateOptions

// TODO: add `sign` function signature. add SignOptions interface
// TODO: add `verify` function signature. add VerifyOptions interface
// TODO: add getPublicKey(options)
// TODO: add getPublicKeyJwk(options)
interface CryptoPrimitive<out T : JWK> {
  /**
   * the algorithm this crypto primitive falls under
   */
  val algorithm: Algorithm

  /**
   * the curve this crypto primitive falls under
   */
  val curve: Curve

  /**
   * identifies the cryptographic algorithm family that this crypto primitive falls under
   */
  val keyType: KeyType

  /**
   * identifies the intended use of this crypto primitive
   */
  val keyUse: KeyUse

  fun generatePrivateKey(): ByteArray

  fun generatePrivateKey(options: GenerateOptions): ByteArray

  fun getPublicKey(privateKeyBytes: ByteArray): ByteArray

  fun generatePrivateKeyJwk(): T

  fun generatePrivateKeyJwk(options: GenerateOptions): T

  fun getPublicKeyJwk(privateKeyJwk: PrivateKeyJwk): JWK

  fun privateKeyToJwk(privateKeyBytes: ByteArray): T

  fun publicKeyToJwk(publicKeyBytes: ByteArray): JWK
}