package web5.sdk.dids

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class DidWebApiTest {

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
        DidWebApi.resolve(testCase.did)
      }

      assertEquals(testCase.expectedExceptionMessage, exception.message)
    }
  }

  @Test
  fun resolve() {
    val result = DidWebApi {
      engine = mockEngine()
    }.resolve("did:web:example.com")
    assertEquals("did:web:example.com", result.didDocument.id.toString())
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