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

    val alias = keyManager.import(privateKey)

    val publicKey = keyManager.getPublicKey(alias)
    assertEquals(privateKey.kid, publicKey.kid)
    assertEquals(privateKey.crv, publicKey.crv)
    assertEquals(privateKey.alg, publicKey.alg)
    assertEquals(privateKey.use, publicKey.use)
    assertEquals(privateKey.x, publicKey.x)
  }

  @Test
  fun `public keys can be imported`() {
    val privateKey = Crypto.generatePrivateKey(AlgorithmId.secp256k1)
    val keyManager = InMemoryKeyManager()

    val alias = keyManager.import(privateKey)
    val publicKey = keyManager.getPublicKey(alias)
    assertEquals(privateKey.kid, publicKey.kid)
    assertEquals(privateKey.crv, publicKey.crv)
    assertEquals(privateKey.alg, publicKey.alg)
    assertEquals(privateKey.use, publicKey.use)
    assertEquals(privateKey.x, publicKey.x)
  }

  @Test
  fun `key without kid can be imported`() {
    val privateKey = Ed25519.generatePrivateKey()
    val keyManager = InMemoryKeyManager()

    val alias = keyManager.import(privateKey)
    val publicKey = keyManager.getPublicKey(alias)
    assertEquals(privateKey.kid, publicKey.kid)
    assertEquals(privateKey.crv, publicKey.crv)
    assertEquals(privateKey.alg, publicKey.alg)
    assertEquals(privateKey.use, publicKey.use)
    assertEquals(privateKey.x, publicKey.x)

  }

  @Test
  fun `export returns all keys`() {
    val keyManager = InMemoryKeyManager()
    keyManager.generatePrivateKey(AlgorithmId.Ed25519)

    val keySet = keyManager.export()
    assertEquals(1, keySet.size)
  }

  @Test
  fun `import throws an exception if key is not a Jwk`() {
    val keyManager = InMemoryKeyManager()
    val kakaKeySet = listOf(mapOf("hehe" to "troll"))

    assertThrows<MissingKotlinParameterException> {
      keyManager.import(kakaKeySet)
    }
  }

  @Test
  fun `import loads all keys provided`() {
    @Suppress("MaxLineLength")
    val serializedKeySet =
      """[{"kty":"OKP","d":"DTwtf9i7M4Vj8vSg0iJAQ_n2gSNEUTNLIq30CJ4d9BE","use":"sig","crv":"Ed25519","kid":"hKTpA-TQPNAX9zXtuxPIyTNpoyd4j1Pq1Y_txo2Hm3I","x":"_CrbbGuhpHFs3KVGg2bbNgd2SikmT4L5rIE_zQQjKq0","alg":"EdDSA"}]"""

    val jsonKeySet: List<Map<String, Any>> = Json.jsonMapper.readValue(serializedKeySet)
    val keyManager = InMemoryKeyManager()

    assertDoesNotThrow {
      keyManager.import(jsonKeySet)
    }
  }
}
