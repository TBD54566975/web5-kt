package web5.sdk.dids.methods.jwk

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import web5.sdk.common.Convert
import web5.sdk.common.Json
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.Jwa
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.DidResolvers
import web5.sdk.dids.exceptions.InvalidMethodNameException
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.testing.TestVectors
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

      val didResolutionResult = DidResolvers.resolve(did.did.uri)
      val verificationMethod = didResolutionResult.didDocument!!.verificationMethod?.get(0)

      assertNotNull(verificationMethod)

      val jwk = verificationMethod.publicKeyJwk
      assertNotNull(jwk)
      val keyAlias = did.keyManager.getDeterministicAlias(jwk)
      val publicKey = did.keyManager.getPublicKey(keyAlias)
      assertEquals(Jwa.ES256K.name, publicKey.alg)
    }
  }

  @Nested
  inner class ImportTest {
    @Test
    fun `importing a portable did jwk did works`() {
      val manager = InMemoryKeyManager()
      val bearerDid = DidJwk.create(manager)
      val portableDid = bearerDid.export()
      val importedDid = DidJwk.import(portableDid, manager)
      assertEquals(bearerDid.did.uri, importedDid.did.uri)
    }

    @Test
    fun `importing a did with wrong method name throws exception`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)
      val portableDid = did.export()
      assertThrows<InvalidMethodNameException> {
        DidJwk.import(portableDid, manager)
      }
    }
  }

  @Nested
  inner class ResolveTest {

    @Test
    fun `throws exception if did cannot be parsed`() {
      val result = DidJwk.resolve("did:jwk:invalid")
      assertEquals("invalidDid", result.didResolutionMetadata.error)
    }

    @Test
    fun `throws exception if did method is not jwk`() {
      val result = DidJwk.resolve("did:example:123")
      assertEquals("methodNotSupported", result.didResolutionMetadata.error)
    }

    @Test
    fun `private key throws exception`() {
      val manager = InMemoryKeyManager()
      manager.generatePrivateKey(AlgorithmId.secp256k1)
      val privateJwkString = Json.parse<Jwk>(manager.export().first().toString())
      val encodedPrivateJwk = Convert(privateJwkString).toBase64Url()

      val did = "did:jwk:$encodedPrivateJwk"
      assertThrows<IllegalArgumentException>(
        "decoded jwk value cannot be a private key"
      ) { DidJwk.resolve(did) }
    }

    @Test
    fun `test vector 1`() {
      // test vector taken from: https://github.com/quartzjer/did-jwk/blob/main/spec.md#p-256
      val did =
        "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFa" +
          "koydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00Nkdx" +
          "RHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
      val result = DidJwk.resolve(did)
      assertNotNull(result)

      val didDocument = result.didDocument
      assertNotNull(didDocument)

      val expectedJson = File("src/test/resources/did_jwk_p256_document.json").readText()
      assertEquals(
        JsonCanonicalizer(expectedJson).encodedString,
        JsonCanonicalizer(Json.stringify(didDocument)).encodedString
      )
    }

    @Test
    fun `test vector 2`() {
      // test vector taken from: https://github.com/quartzjer/did-jwk/blob/main/spec.md#x25519
      val did =
        "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZY" +
          "dDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
      val result = DidJwk.resolve(did)
      assertNotNull(result)

      val didDocument = result.didDocument
      assertNotNull(didDocument)

      val expectedJson = File("src/test/resources/did_jwk_x25519_document.json").readText()
      assertEquals(
        JsonCanonicalizer(expectedJson).encodedString,
        JsonCanonicalizer(Json.stringify(didDocument)).encodedString
      )
    }
  }
}

class Web5TestVectorsDidJwk {
  private val mapper = jacksonObjectMapper()

  @Test
  fun resolve() {
    val typeRef = object : TypeReference<TestVectors<String, DidResolutionResult>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/did_jwk/resolve.json"), typeRef)

    testVectors.vectors.forEach { vector ->
      val resolutionResult = DidJwk.resolve(vector.input)
      assertEquals(vector.output, resolutionResult, vector.description)
    }
  }
}
