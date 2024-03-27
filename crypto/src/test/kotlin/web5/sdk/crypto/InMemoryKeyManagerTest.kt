package web5.sdk.crypto

import com.fasterxml.jackson.module.kotlin.MissingKotlinParameterException
import com.fasterxml.jackson.module.kotlin.readValue
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.common.Json
import kotlin.test.assertEquals

class InMemoryKeyManagerTest {
  @Test
  fun `test alias is consistent`() {
    val keyManager = InMemoryKeyManager()
    val alias = keyManager.generatePrivateKey(AlgorithmId.secp256k1)
    val publicKey = keyManager.getPublicKey(alias)
    val defaultAlias = keyManager.getDeterministicAlias(publicKey)

    assertEquals(alias, defaultAlias)
  }

  @Test
  fun `exception is thrown when kid not found`() {
    val keyManager = InMemoryKeyManager()
    val jwk = Crypto.generatePrivateKey(AlgorithmId.secp256k1)
    val exception = assertThrows<IllegalArgumentException> {
      keyManager.getDeterministicAlias(jwk)
    }
    assertTrue(exception.message!!.matches("key with alias .* not found".toRegex()))
  }

  @Test
  fun `public key is available after import`() {
    val privateKey = Crypto.generatePrivateKey(AlgorithmId.secp256k1)
    val keyManager = InMemoryKeyManager()

    val alias = keyManager.importKey(privateKey)

    val publicKey = keyManager.getPublicKey(alias)
    assertEquals(privateKey.kty, publicKey.kty)
    assertEquals(privateKey.crv, publicKey.crv)
    assertEquals(privateKey.x, publicKey.x)
  }

  @Test
  fun `public keys can be imported`() {
    val privateKey = Crypto.generatePrivateKey(AlgorithmId.secp256k1)
    val keyManager = InMemoryKeyManager()

    val alias = keyManager.importKey(privateKey)
    val publicKey = keyManager.getPublicKey(alias)
    assertEquals(privateKey.kty, publicKey.kty)
    assertEquals(privateKey.crv, publicKey.crv)
    assertEquals(privateKey.x, publicKey.x)
  }

  @Test
  fun `key without kid can be imported`() {
    val privateKey = Ed25519.generatePrivateKey()
    val keyManager = InMemoryKeyManager()

    val alias = keyManager.importKey(privateKey)
    val publicKey = keyManager.getPublicKey(alias)
    assertEquals(privateKey.kty, publicKey.kty)
    assertEquals(privateKey.crv, publicKey.crv)
    assertEquals(privateKey.x, publicKey.x)

  }

}
