package web5.sdk.dids.methods.web

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
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

      else -> throw Exception("")
    }
  }
}