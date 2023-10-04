
import com.nimbusds.jose.jwk.Curve
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.erdtman.jcs.JsonCanonicalizer
import web5.dids.DIDIonManager
import web5.dids.ion.model.JsonWebKey
import web5.dids.ion.model.PublicKey
import web5.dids.ion.model.PublicKeyPurpose
import web5.dids.ion.model.SidetreeCreateOperation
import java.io.File
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals


class DIDIonTest {

  @Test
  @Ignore("For demonstration purposes only - this makes a network call")
  fun createWithDefault() = runTest {
    val (did, doc, metadata) = DIDIonManager.create()
    assertContains(did.didString, "did:ion:")
    assertEquals(1, doc.verificationMethods.size)
    assertEquals(did.didString, metadata.longFormDID)
    assertContains(metadata.longFormDID, metadata.shortFormDID)
  }
  @Test
  fun createWithCustom() = runTest {
    val verificationKey = readKey("src/test/resources/verification_jwk.json")
    val updateKey = readKey("src/test/resources/update_jwk.json")
    val recoveryKey = readKey("src/test/resources/recovery_jwk.json")
    val c = DIDIonManager {
      ionHost = "madeuphost"
      engine = mockEngine()
      updatePublicJsonWebKey = updateKey
      verificationPublicKey = PublicKey(
        id = verificationKey.kid!!,
        type = Curve.SECP256K1.name,
        publicKeyJWK = verificationKey,
        purposes = listOf(PublicKeyPurpose.AUTHENTICATION),
      )
      recoveryJsonWebKey = recoveryKey
    }
    val (did, _, metadata) = c.create()
    assertContains(did.toString(), "did:ion:")
    assertContains(metadata.longFormDID, metadata.shortFormDID)
  }

  private fun readKey(pathname: String): JsonWebKey {
    return Json.decodeFromString<JsonWebKey>(
      File(pathname).readText())
  }

  @Test
  fun `serializing and deserializing produces the same create operation`() {
    val jsonContent = File("src/test/resources/create_operation.json").readText()
    val expectedContent = JsonCanonicalizer(jsonContent).encodedString

    val createOperation = Json.decodeFromString<SidetreeCreateOperation>(jsonContent)

    val jsonString = Json.encodeToString(createOperation)
    assertEquals(expectedContent, JsonCanonicalizer(jsonString).encodedString)
  }

  @Test
  fun `create returns the correct longform and short form dids`() = runTest {
    val (did, _, metadata) = DIDIonManager {
      engine = mockEngine()
    }.create()

    assertContains(did.toString(), "did:ion:")
    assertContains(metadata.longFormDID, metadata.shortFormDID)
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