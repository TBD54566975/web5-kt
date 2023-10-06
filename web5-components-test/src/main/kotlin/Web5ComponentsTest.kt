import com.fasterxml.jackson.annotation.JsonProperty
import io.ktor.application.*
import io.ktor.features.ContentNegotiation
import io.ktor.jackson.jackson
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import web5.credentials.model.CredentialSubject
import web5.credentials.model.VerifiableCredentialType
import java.net.URI
import java.util.Date

/**
 * Represents a [CredentialIssuanceRequest].
 */
public data class CredentialIssuanceRequest(
  val credential: Credential,
)

/**
 * Represents a [Credential] for a request.
 */
public data class Credential(
  @JsonProperty("@context") val context: List<String>,
  val id: String,
  val type: List<String>,
  val issuer: String,
  val credentialSubject: Map<String, Any>
)

/**
 * Entry point of the application.
 *
 * Describe any additional details about the function, its parameters, and its behavior here.
 */
public fun main() {
  val server = embeddedServer(Netty, port = 8081) {
    app()
  }

  server.start(wait = true)
}

private fun Application.app() {
  install(ContentNegotiation) {
    jackson { }
  }

  routing {
    get("/ready") {
      call.respondText("ok")
    }

    post("/credentials/unsigned") {
      var requestBody: CredentialIssuanceRequest? = null
      try {
        requestBody = call.receive()
      } catch (e: Exception) {
        println("Error receiving the request body: ${e.message}")
      }

      val credentialSubject = CredentialSubject.builder()
        .id(URI.create(requestBody?.credential?.credentialSubject?.get("id").toString()))
        .claims(mutableMapOf<String, Any>().apply {
          this["firstName"] =
            requestBody?.credential?.credentialSubject?.get("firstName").toString()
        })
        .build()

      val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
        .id(URI.create(requestBody?.credential?.id))
        .credentialSubject(credentialSubject)
        .issuer(URI.create(requestBody?.credential?.issuer))
        .issuanceDate(Date())
        .build()

      call.respond(vc)
    }
  }
}
