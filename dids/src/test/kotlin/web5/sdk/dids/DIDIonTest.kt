package web5.sdk.dids

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutputStreamContent
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import web5.dids.ion.model.PublicKey
import web5.dids.ion.model.PublicKeyPurpose
import web5.dids.ion.model.Service
import web5.dids.ion.model.SidetreeCreateOperation
import web5.dids.ion.model.SidetreeUpdateOperation
import web5.sdk.crypto.InMemoryKeyManager
import java.io.File
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DIDIonTest {

  @Test
  @Ignore("For demonstration purposes only - this makes a network call")
  fun createWithDefault() {
    val (did, _) = DIDIonManager.create(InMemoryKeyManager())
    assertContains(did.uri, "did:ion:")
  }

  @Test
  fun createWithCustom() {
    val keyManager = InMemoryKeyManager()
    val verificationKey = readKey("src/test/resources/verification_jwk.json")
    val updateKey = readKey("src/test/resources/update_jwk.json")
    val recoveryKey = readKey("src/test/resources/recovery_jwk.json")
    val manager = DIDIonManager {
      ionHost = "madeuphost"
      engine = mockEngine()
    }
    val opts = CreateDidIonOptions(
      verificationPublicKey = PublicKey(
        id = verificationKey.keyID,
        type = "JsonWebKey2020",
        publicKeyJwk = verificationKey,
        purposes = listOf(PublicKeyPurpose.AUTHENTICATION),
      ),
      updatePublicJWK = updateKey,
      recoveryPublicJWK = recoveryKey
    )
    val (did, metadata) = manager.create(keyManager, opts)
    assertContains(did.uri, "did:ion:")
    assertContains(metadata.longFormDID, metadata.shortFormDID)
  }

  private fun readKey(pathname: String): JWK {
    return JWK.parse(
      File(pathname).readText()
    )
  }

  @Test
  fun `serializing and deserializing produces the same create operation`() {
    val jsonContent = File("src/test/resources/create_operation.json").readText()
    val expectedContent = JsonCanonicalizer(jsonContent).encodedString

    val mapper = jacksonObjectMapper()
    val createOperation = mapper.readValue<SidetreeCreateOperation>(jsonContent)

    val jsonString = mapper.writeValueAsString(createOperation)
    assertEquals(expectedContent, JsonCanonicalizer(jsonString).encodedString)
  }

  @Test
  fun `create changes the key manager state`() {
    val keyManager = InMemoryKeyManager()
    val (did, metadata) = DIDIonManager {
      engine = mockEngine()
    }.create(keyManager)

    assertContains(did.uri, "did:ion:")
    assertContains(metadata.longFormDID, metadata.shortFormDID)
    assertDoesNotThrow {
      keyManager.getPublicKey(metadata.keyAliases.recoveryKeyAlias)
      keyManager.getPublicKey(metadata.keyAliases.updateKeyAlias)
      keyManager.getPublicKey(metadata.keyAliases.verificationKeyAlias)
    }
  }

  @Test
  fun `update fails when update key is absent`() {
    val result = assertThrows<Exception> {
      DIDIonManager.update(
        InMemoryKeyManager(),
        UpdateDidIonOptions(
          didString = "did:ion:123",
          updateKeyAlias = "my_fake_key",
        )
      )
    }
    assertEquals("key with alias my_fake_key not found", result.message)
  }

  @Test
  fun `update sends the expected operation`() {
    val mapper = jacksonObjectMapper()

    val keyManager: InMemoryKeyManager = spy(InMemoryKeyManager())

    val updateKey = readKey("src/test/resources/jwkEs256k1Private.json")
    val updateKeyId = keyManager.import(updateKey)

    val nextUpdateKey = readKey("src/test/resources/jwkEs256k2Public.json")
    val nextUpdateKeyId = keyManager.import(nextUpdateKey)
    doReturn(nextUpdateKeyId).whenever(keyManager).generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1)

    val service: Service = mapper.readValue(File("src/test/resources/service1.json").readText())
    val publicKey1: PublicKey = mapper.readValue(
      File("src/test/resources/publicKeyModel1.json").readText()
    )

    val validatinMockEngine = MockEngine { request ->
      val updateOp: SidetreeUpdateOperation = mapper.readValue((request.body as OutputStreamContent).toByteArray())
      assertEquals("EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", updateOp.didSuffix)
      assertEquals("update", updateOp.type)
      assertEquals("EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ", updateOp.revealValue)
      val jws = JWSObject.parse(updateOp.signedData)
      assertEquals("eyJhbGciOiJFUzI1NksifQ", jws.header.toBase64URL().toString())
      assertEquals(
        "eyJ1cGRhdGVLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDB" +
          "leUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdh" +
          "Q004RjdrIn0sImRlbHRhSGFzaCI6IkVpQXZsbVVRYy1jaDg0Slp5bmdQdkJzUkc3eWh4aUFSenlYOE5lNFQ4LTlyTncifQ",
        jws.payload.toBase64URL().toString()
      )
      val verifier = DefaultJWSVerifierFactory().createJWSVerifier(jws.header, updateKey.toECKey().toPublicKey())
      verifier.jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
      assertTrue(jws.verify(verifier))
      assertEquals("EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA", updateOp.delta.updateCommitment)
      assertEquals(4, updateOp.delta.patches.size)
      respond(
        content = ByteReadChannel("""{"hello":"world"}"""),
        headers = headersOf(HttpHeaders.ContentType, "application/json"),
        status = HttpStatusCode.OK,
      )
    }
    val updateMetadata = DIDIonManager {
      engine = validatinMockEngine
    }.update(
      keyManager,
      UpdateDidIonOptions(
        didString = "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        updateKeyAlias = updateKeyId,
        servicesToAdd = listOf(service),
        idsOfServicesToRemove = setOf("someId1"),
        publicKeysToAdd = listOf(publicKey1),
        idsOfPublicKeysToRemove = setOf("someId2"),
      ),
    )

    assertTrue(updateMetadata.updateKeyAlias.isNotEmpty())
    assertEquals("""{"hello":"world"}""", updateMetadata.operationsResponseBody)
  }

  private fun mockEngine() = MockEngine { request ->
    when (request.url.encodedPath) {
      "/operations" -> {
        respond(
          content = ByteReadChannel("""{}"""),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      else -> respond(
        content = ByteReadChannel(File("src/test/resources/basic_did_resolution.json").readText()),
        status = HttpStatusCode.OK,
        headers = headersOf(HttpHeaders.ContentType, "application/json")
      )
    }
  }
}