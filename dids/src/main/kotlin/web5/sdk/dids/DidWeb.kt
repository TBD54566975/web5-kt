package web5.sdk.dids

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.serialization.jackson.jackson
import kotlinx.coroutines.runBlocking
import web5.sdk.crypto.KeyManager
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Provides a specific implementation for creating and resolving "did:web" method Decentralized Identifiers (DIDs).
 *
 * A "did:web" DID is an implementation that uses the web domains existing reputation system. More details can be
 * read in https://w3c-ccg.github.io/did-method-web/
 *
 * @property uri The URI of the "did:web" which conforms to the DID standard.
 * @property keyManager A [KeyManager] instance utilized to manage the cryptographic keys associated with the DID.
 *
 * ### Usage Example:
 * ```kotlin
 * val keyManager = InMemoryKeyManager()
 * val did = StatefulWebDid("did:web:tbd.website", keyManager)
 * ```
 */
public class DidWeb(
  uri: String,
  keyManager: KeyManager
) : Did(uri, keyManager)

/**
 * Configuration options for the [DidWebApi].
 *
 * - [engine] is used to override the default ktor engine, which is [CIO].
 */
public class DidWebApiConfiguration internal constructor(
  public var engine: HttpClientEngine? = CIO.create { },
)

/**
 * Returns a [DidWebApi] instance after applying [blockConfiguration].
 */
public fun DidWebApi(blockConfiguration: DidWebApiConfiguration.() -> Unit): DidWebApi {
  val conf = DidWebApiConfiguration().apply(blockConfiguration)
  return DidWebApiImpl(conf)
}

private class DidWebApiImpl(configuration: DidWebApiConfiguration) : DidWebApi(configuration)

private const val wellKnownURLPath = ".well-known/"
private const val didDocFilename = "did.json"

/**
 * Implements [resolve] and [create] according to https://w3c-ccg.github.io/did-method-web/
 */
public sealed class DidWebApi(
  configuration: DidWebApiConfiguration
) : DidMethod<DidWeb, CreateDidOptions> {

  private val mapper = jacksonObjectMapper()

  private val engine: HttpClientEngine = configuration.engine ?: CIO.create {}

  private val client = HttpClient(engine) {
    install(ContentNegotiation) {
      jackson { mapper }
    }
  }

  override val methodName: String = "web"

  override fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
    val docURL = getDocURL(did)

    val resp = runBlocking {
      client.get(docURL) {
        contentType(ContentType.Application.Json)
      }
    }

    val body = runBlocking { resp.bodyAsText() }

    if (!resp.status.isSuccess()) {
      throw InvalidStatusException(resp.status.value, "resolution error response: '$body'")
    }
    return DidResolutionResult(
      didDocument = mapper.readValue(body, DIDDocument::class.java),
    )
  }

  private fun getDocURL(didWebStr: String): String {
    val parsedDid = DID.fromString(didWebStr)
    require(parsedDid.methodName == methodName) {
      "$didWebStr is missing prefix \"did:$methodName\""
    }

    val subStrs = parsedDid.methodSpecificId.split(":")

    val decodedDomain = URLDecoder.decode(subStrs[0], StandardCharsets.UTF_8)

    return if (subStrs.size == 1) {
      "https://$decodedDomain/$wellKnownURLPath$didDocFilename"
    } else {
      val urlBuilder = StringBuilder()
      urlBuilder.append("https://$decodedDomain/")
      for (i in 1 until subStrs.size) {
        val str = URLDecoder.decode(subStrs[i], StandardCharsets.UTF_8)
        urlBuilder.append("$str/")
      }
      urlBuilder.append(didDocFilename)
      urlBuilder.toString()
    }
  }

  public override fun create(keyManager: KeyManager, options: CreateDidOptions?): DidWeb {
    throw RuntimeException("create operation not supported for did:web")
  }

  /** A [DidWebApi] with default [DidWebApiConfiguration] parameters. */
  public companion object Default : DidWebApi(DidWebApiConfiguration())
}