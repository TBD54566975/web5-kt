package web5.sdk.dids

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.jwk.JWK
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.assertDoesNotThrow
import web5.dids.ion.model.PublicKey
import web5.dids.ion.model.PublicKeyPurpose
import web5.dids.ion.model.SidetreeCreateOperation
import web5.sdk.crypto.InMemoryKeyManager
import java.io.File
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals

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