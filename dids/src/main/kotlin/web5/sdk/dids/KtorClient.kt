package web5.sdk.dids

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.jackson.jackson
import kotlinx.coroutines.runBlocking

/** HttpClient implementation using ktor. */
public class KtorClient(
  engine: HttpClientEngine = CIO.create { },
  private val mapper: ObjectMapper = jacksonObjectMapper()) : web5.sdk.dids.HttpClient {

  private val client = HttpClient(engine) {
    install(ContentNegotiation) {
      jackson { mapper }
    }
  }

  override fun post(url: String, body: Any): HttpResponse {
    val response = runBlocking {
      client.post(url) {
        contentType(ContentType.Application.Json)
        setBody(body)
      }
    }
    val opBody = runBlocking {
      response.bodyAsText()
    }
    return HttpResponse(opBody, response.status.toStatus())
  }

  override fun get(url: String): HttpResponse {
    val resp = runBlocking { client.get(url) }
    val body = runBlocking { resp.bodyAsText() }
    return HttpResponse(body, resp.status.toStatus())
  }
}

/** Creates a [HttpStatus] from a ktor [HttpStatusCode]. */
public fun HttpStatusCode.toStatus(): HttpStatus {
  return HttpStatus(this.value, this.description)
}