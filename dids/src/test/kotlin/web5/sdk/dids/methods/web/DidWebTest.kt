package web5.sdk.dids.methods.web

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.util.readKey
import java.io.File
import kotlin.test.assertEquals

class DidWebTest {

  @Test
  fun `badly formed dids throw exceptions`() {
    class TestCase(
      val did: String,
      val expectedExceptionMessage: String,
    )

    val testCases = listOf(
      TestCase(
        did = "did:ion:wrongprefix",
        expectedExceptionMessage = "did:ion:wrongprefix is missing prefix \"did:web\""
      ),
      TestCase(
        did = "did:web:",
        expectedExceptionMessage = "Cannot parse DID: did:web:"
      ),
    )
    for (testCase in testCases) {
      val exception = assertThrows<Exception> {
        DidWeb.resolve(testCase.did)
      }

      assertEquals(testCase.expectedExceptionMessage, exception.message)
    }
  }

  @Test
  fun resolve() {
    val didsToTest = listOf(
      "did:web:example.com",
      "did:web:w3c-ccg.github.io:user:alice",
      "did:web:example.com%3A3000:user:alice",
    )
    val api = DidWebApi {
      engine = mockEngine()
    }
    for (did in didsToTest) {
      val result = api.resolve(did)
      assertEquals(did, result.didDocument.id.toString())
    }
  }

  @Test
  fun `load returns instance when key manager contains private key`() {
    val manager = InMemoryKeyManager()
    val privateJwk = readKey("src/test/resources/jwkEs256k1Private.json")
    manager.import(privateJwk)
    DidWebApi {
      engine = mockEngine()
    }.load("did:web:example-with-verification-method.com", manager)
  }

  @Test
  fun `load throws exception when key manager does not contain private key`() {
    val manager = InMemoryKeyManager()
    val exception = assertThrows<IllegalArgumentException> {
      DidWebApi {
        engine = mockEngine()
      }.load("did:web:example-with-verification-method.com", manager)
    }
    assertEquals("key with alias CfveyLOfYrOhSgD66MA6PO9J5sAnj_J-Z0URcD6VGVU not found", exception.message)
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

      "https://w3c-ccg.github.io/user/alice/did.json" -> {
        respond(
          content = ByteReadChannel("""{"id": "did:web:w3c-ccg.github.io:user:alice"}"""),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      "https://example.com:3000/user/alice/did.json" -> {
        respond(
          content = ByteReadChannel("""{"id": "did:web:example.com%3A3000:user:alice"}"""),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      "https://example-with-verification-method.com/.well-known/did.json" -> {
        respond(
          content = ByteReadChannel(
            File("src/test/resources/did_document_jwkEx256k1Public_assertion.json").readText()
          ),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      else -> throw Exception("")
    }
  }
}