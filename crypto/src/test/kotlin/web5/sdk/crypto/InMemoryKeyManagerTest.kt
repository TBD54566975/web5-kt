package web5.sdk.crypto

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import java.text.ParseException
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
  fun `exception is thrown when kid not found`() {
    val keyManager = InMemoryKeyManager()
    val jwk = Crypto.generatePrivateKey(JWSAlgorithm.ES256K)
    val exception = assertThrows<IllegalArgumentException> {
      keyManager.getDeterministicAlias(jwk.toPublicJWK())
    }
    assertTrue(exception.message!!.matches("key with alias .* not found".toRegex()))
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

  @Test
  fun `import throws an exception if key isnt a JWK`() {
    val keyManager = InMemoryKeyManager()
    val kakaKeySet = listOf(mapOf("hehe" to "troll"))

    assertThrows<ParseException> {
      keyManager.import(kakaKeySet)
    }
  }

  @Test
  fun `import loads all keys provided`() {
    @Suppress("MaxLineLength")
    val serializedKeySet =
      """[{"kty":"OKP","d":"DTwtf9i7M4Vj8vSg0iJAQ_n2gSNEUTNLIq30CJ4d9BE","use":"sig","crv":"Ed25519","kid":"hKTpA-TQPNAX9zXtuxPIyTNpoyd4j1Pq1Y_txo2Hm3I","x":"_CrbbGuhpHFs3KVGg2bbNgd2SikmT4L5rIE_zQQjKq0","alg":"EdDSA"}]"""

    val jsonMapper: ObjectMapper = ObjectMapper()
      .findAndRegisterModules()
      .setSerializationInclusion(JsonInclude.Include.NON_NULL)

    val jsonKeySet: List<Map<String, Any>> = jsonMapper.readValue(serializedKeySet)
    val keyManager = InMemoryKeyManager()

    assertDoesNotThrow {
      keyManager.import(jsonKeySet)
    }
  }
}
