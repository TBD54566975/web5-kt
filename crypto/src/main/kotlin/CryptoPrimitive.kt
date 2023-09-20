package web5.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse

typealias PrivateKeyJwk = JWK
typealias PublicKeyJwk = JWK

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

  fun getPublicKey(privateKeyBytes: ByteArray): ByteArray

  fun generatePrivateKeyJwk(): T

  fun getPublicKeyJwk(privateKeyJwk: PrivateKeyJwk): JWK

  fun privateKeyToJwk(privateKeyBytes: ByteArray): T

}