package web5.sdk.dids.methods.jwk

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import web5.sdk.common.Convert
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.DidResolvers
import web5.sdk.testing.TestVectors
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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
  inner class LoadTest {
    @Test
    fun `throws exception when key manager does not contain private key`() {
      val manager = InMemoryKeyManager()
      val exception = assertThrows<IllegalArgumentException> {
        @Suppress("MaxLineLength")
        DidJwk.load(
          "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
          manager
        )
      }
      assertEquals("key with alias wKIg-QPOd75_AJLdvvo-EACSpCPE5IOJu-MUpQVk1c4 not found", exception.message)
    }

    @Test
    fun `returns instance when key manager contains private key`() {
      val manager = InMemoryKeyManager()
      val did = DidJwk.create(manager)
      val didKey = DidJwk.load(did.uri, manager)
      assertEquals(did.uri, didKey.uri)
    }

    @Test
    fun `throws exception when loading a different type of did`() {
      val manager = InMemoryKeyManager()
      val did = DidJwk.create(manager)
      val exception = assertThrows<IllegalArgumentException> {
        DidJwk.load(did.uri.replace("jwk", "ion"), manager)
      }
      assertTrue(exception.message!!.startsWith("did must start with the prefix \"did:jwk\""))
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

class Web5TestVectorsDidJwkTest {
  private val mapper = jacksonObjectMapper()

  @Test
  fun resolve() {
    val typeRef = object : TypeReference<TestVectors<String, DidResolutionResult>>() {}
    val testVectors = mapper.readValue(File("../test-vectors/did_jwk/resolve.json"), typeRef)

    testVectors.vectors.forEach { vector ->
      val resolutionResult = DidJwk.resolve(vector.input)
      assertEquals(vector.output, resolutionResult, vector.description)
    }
  }
}