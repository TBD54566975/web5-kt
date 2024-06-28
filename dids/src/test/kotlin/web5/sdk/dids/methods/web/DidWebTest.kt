package web5.sdk.dids.methods.web

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.junit.jupiter.api.Test
import web5.sdk.dids.DidResolutionResult
import web5.sdk.testing.TestVectors
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class DidWebTest {

  @Test
  fun `badly formed dids return resolution errors`() {
    class TestCase(
      val did: String,
      val expectedError: String,
    )

    val testCases = listOf(
      TestCase(
        did = "did:ion:wrongprefix",
        expectedError = "methodNotSupported"
      ),
      TestCase(
        did = "did:web:",
        expectedError = "invalidDid"
      ),
    )
    for (testCase in testCases) {
      val resolutionResult = DidWeb.resolve(testCase.did)

      assertEquals(testCase.expectedError, resolutionResult.didResolutionMetadata.error)
    }
  }

  @Test
  fun resolve() {
    val didsToTest = listOf(
      "did:web:example.com",
      "did:web:example.com%3A8080",
      "did:web:w3c-ccg.github.io:user:alice",
      "did:web:example.com%3A3000:user:alice",
      "did:web:localhost",
      "did:web:localhost%3A8080",
      "did:web:127.0.0.1",
    )
    val api = DidWebApi {
      engine = mockEngine()
    }
    for (did in didsToTest) {
      val result = api.resolve(did)
      val didDocument = assertNotNull(result.didDocument, "document should not be null for $did")
      assertEquals(did, didDocument.id)
    }
  }

  @Test
  fun `resolve returns internal error when http fails`() {
    val result = DidWebApi {
      engine = MockEngine {
        respond("some failure", HttpStatusCode.InternalServerError)
      }
    }.resolve("did:web:example.com")

    assertEquals("internalError", result.didResolutionMetadata.error)
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

      "https://example.com:8080/.well-known/did.json" -> {
        respond(
          content = ByteReadChannel("""{"id": "did:web:example.com%3A8080"}"""),
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

      // localhost (& loopback IP 127.0.0.1) use http

      "http://localhost/.well-known/did.json" -> {
        respond(
          content = ByteReadChannel("""{"id": "did:web:localhost"}"""),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      "http://localhost:8080/.well-known/did.json" -> {
        respond(
          content = ByteReadChannel("""{"id": "did:web:localhost%3A8080"}"""),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      "http://127.0.0.1/.well-known/did.json" -> {
        respond(
          content = ByteReadChannel("""{"id": "did:web:127.0.0.1"}"""),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      else -> throw Exception("")
    }
  }
}

class Web5TestVectorsDidWeb {
  data class ResolveTestInput(
    val didUri: String,
    val mockServer: Map<String, JsonNode>?,
  )

  private val mapper = jacksonObjectMapper()

  @Test
  fun resolve() {
    val typeRef = object : TypeReference<TestVectors<ResolveTestInput, DidResolutionResult>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/did_web/resolve.json"), typeRef)

    testVectors.vectors.forEach { vector ->
      val resolutionResult = DidWebApi {
        engine = vector.input.mockServer?.let {
          mockEngine(it)
        }
      }.resolve(vector.input.didUri)
      assertEquals(vector.output, resolutionResult, vector.description)
    }
  }

  private fun mockEngine(mockServer: Map<String, JsonNode>): MockEngine {
    return MockEngine { request ->
      if (mockServer.containsKey(request.url.toString())) {
        respond(
          content = ByteReadChannel(mockServer[request.url.toString()]!!.toString()),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      } else throw Exception("Mock server does not contain ${request.url}")
    }

  }
}