package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType

public interface KeyGenOptions

public interface KeyGenerator {
  public val algorithm: Algorithm
  public val keyType: KeyType
  public fun generatePrivateKey(options: KeyGenOptions? = null): JWK

  public fun getPublicKey(privateKey: JWK): JWK

  public fun privateKeyToBytes(privateKey: JWK): ByteArray

  public fun publicKeyToBytes(publicKey: JWK): ByteArray

  public fun bytesToPrivateKey(privateKeyBytes: ByteArray): JWK

  public fun bytesToPublicKey(publicKeyBytes: ByteArray): JWK
}