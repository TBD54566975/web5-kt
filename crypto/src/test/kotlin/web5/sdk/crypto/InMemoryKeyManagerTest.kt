package web5.sdk.crypto

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import kotlin.test.assertEquals

class InMemoryKeyManagerTest {
  @Test
  fun `test alias is consistent`() {
    val keyManager = InMemoryKeyManager()
    val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val publicKey = keyManager.getPublicKey(alias)
    val defaultAlias = keyManager.getDeterministicAlias(publicKey)

    assertEquals(alias, defaultAlias)
  }

  @Test
  fun `public key is available after import`() {
    val jwk = Crypto.generatePrivateKey(JWSAlgorithm.ES256K)
    val keyManager = InMemoryKeyManager()

    val alias = keyManager.import(jwk)

    val publicKey = keyManager.getPublicKey(alias)
    assertEquals(jwk.toPublicJWK(), publicKey)
  }

  @Test
  fun `public keys can be imported`() {
    val jwk = Crypto.generatePrivateKey(JWSAlgorithm.ES256K)
    val keyManager = InMemoryKeyManager()

    val alias = keyManager.import(jwk.toPublicJWK())

    assertEquals(jwk.toPublicJWK(), keyManager.getPublicKey(alias))
  }

  @Test
  fun `key without kid can be imported`() {
    val jwk = ECKeyGenerator(Curve.SECP256K1).provider(BouncyCastleProviderSingleton.getInstance()).generate()
    val keyManager = InMemoryKeyManager()

    val alias = keyManager.import(jwk)

    val publicKey = keyManager.getPublicKey(alias)
    assertEquals(jwk.toPublicJWK(), publicKey)
  }

  @Test
  fun `export returns all keys`() {
    val keyManager = InMemoryKeyManager()
    keyManager.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)

    val keySet = keyManager.export()
    assertEquals(1, keySet.size)

    assertDoesNotThrow {
      JWK.parse(keySet[0])
    }
  }
}
