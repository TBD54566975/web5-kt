package web5.sdk.dids

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.methods.key.DidKey
import web5.sdk.dids.methods.web.DidWebApi
import java.security.SignatureException
import kotlin.test.assertContains
import kotlin.test.assertEquals

class DidMethodTest {
  @Test
  fun `findAssertionMethodById works with default`() {
    val manager = InMemoryKeyManager()
    val bearerDid = DidKey.create(manager)

    val verificationMethod = DidKey.resolve(bearerDid.did.uri, null)
      .didDocument!!
      .findAssertionMethodById()
    assertEquals("${bearerDid.did.uri}#${Did.parse(bearerDid.did.uri).id}", verificationMethod.id)
  }

  @Test
  fun `findAssertionMethodById finds with id`() {
    val manager = InMemoryKeyManager()
    val bearerDid = DidKey.create(manager)

    val assertionMethodId = "${bearerDid.did.uri}#${Did.parse(bearerDid.did.uri).id}"
    val verificationMethod = DidKey.resolve(bearerDid.did.uri, null)
      .didDocument!!
      .findAssertionMethodById(assertionMethodId)
    assertEquals(assertionMethodId, verificationMethod.id)
  }

  @Test
  fun `findAssertionMethodById throws exception`() {
    val manager = InMemoryKeyManager()
    val bearerDid = DidKey.create(manager)

    val exception = assertThrows<SignatureException> {
      DidKey.resolve(bearerDid.did.uri, null)
        .didDocument!!
        .findAssertionMethodById("made up assertion method id")
    }
    assertContains(exception.message!!, "assertion method \"made up assertion method id\" not found")
  }

  @Test
  fun `findAssertionMethodById throws exception when no assertion methods are found`() {
    val manager = InMemoryKeyManager()
    val did = DidWebApi {
      engine = mockEngine()
    }.load("did:web:example.com", manager)

    val exception = assertThrows<SignatureException> {
      did.resolve(null).didDocument!!.findAssertionMethodById("made up assertion method id")
    }
    assertEquals("No assertion methods found in DID document", exception.message)
  }

  private fun mockEngine() = MockEngine { request ->
    when (request.url.toString()) {
      "https://example.com/.well-known/did.json" -> {
        respond(
          content = ByteReadChannel("""{"id": "did:web:example.com"}"""),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      else -> throw Exception("")
    }
  }
}