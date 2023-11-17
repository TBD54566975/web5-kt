package web5.sdk.dids.methods.jwk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import web5.sdk.common.Convert
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.DidResolvers
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class DidJwkTest {
  @Nested
  inner class CreateTest {
    @Test
    fun `creates an ES256K key when no options are passed`() {
      val manager = InMemoryKeyManager()
      val did = DidJwk.create(manager)

      val didResolutionResult = DidResolvers.resolve(did.uri)
      val verificationMethod = didResolutionResult.didDocument.allVerificationMethods[0]

      assertNotNull(verificationMethod)

      val jwk = JWK.parse(verificationMethod.publicKeyJwk)
      val keyAlias = did.keyManager.getDeterministicAlias(jwk)
      val publicKey = did.keyManager.getPublicKey(keyAlias)

      assertEquals(JWSAlgorithm.ES256K, publicKey.algorithm)
    }
  }

  @Nested
  inner class ResolveTest {
    @Test
    fun `private key throws exception`() {
      val manager = InMemoryKeyManager()
      manager.generatePrivateKey(JWSAlgorithm.ES256K)
      val privateJwk = JWK.parse(manager.export().first())
      val encodedPrivateJwk = Convert(privateJwk.toJSONString()).toBase64Url(padding = false)

      val did = "did:jwk:$encodedPrivateJwk"
      assertThrows<IllegalArgumentException>("decoded jwk value cannot be a private key") { DidJwk.resolve(did) }
    }

    @Test
    fun `test vector 1`() {
      // test vector taken from: https://github.com/quartzjer/did-jwk/blob/main/spec.md#p-256
      @Suppress("MaxLineLength")
      val did =
        "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
      val result = DidJwk.resolve(did)
      assertNotNull(result)

      val didDocument = result.didDocument
      assertNotNull(didDocument)

      val expectedJson = File("src/test/resources/did_jwk_p256_document.json").readText()
      assertEquals(JsonCanonicalizer(expectedJson).encodedString, JsonCanonicalizer(didDocument.toJson()).encodedString)
    }

    @Test
    fun `test vector 2`() {
      // test vector taken from: https://github.com/quartzjer/did-jwk/blob/main/spec.md#x25519
      @Suppress("MaxLineLength")
      val did =
        "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
      val result = DidJwk.resolve(did)
      assertNotNull(result)

      val didDocument = result.didDocument
      assertNotNull(didDocument)

      val expectedJson = File("src/test/resources/did_jwk_x25519_document.json").readText()
      assertEquals(JsonCanonicalizer(expectedJson).encodedString, JsonCanonicalizer(didDocument.toJson()).encodedString)
    }
  }
}