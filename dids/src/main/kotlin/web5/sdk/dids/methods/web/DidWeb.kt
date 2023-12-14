package web5.sdk.dids.methods.web

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
import foundation.identity.did.parser.ParserException
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.serialization.jackson.jackson
import kotlinx.coroutines.runBlocking
import okhttp3.Cache
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.dnsoverhttps.DnsOverHttps
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.CreateDidOptions
import web5.sdk.dids.Did
import web5.sdk.dids.DidMethod
import web5.sdk.dids.DidResolutionMetadata
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.ResolutionErrors
import web5.sdk.dids.ResolveDidOptions
import web5.sdk.dids.methods.ion.InvalidStatusException
import web5.sdk.dids.validateKeyMaterialInsideKeyManager
import java.io.File
import java.net.InetAddress
import java.net.URL
import java.net.URLDecoder
import java.net.UnknownHostException
import kotlin.text.Charsets.UTF_8

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
  keyManager: KeyManager,
  private val didWebApi: DidWebApi
) : Did(uri, keyManager) {
  /**
   * Calls [DidWebApi.resolve] for this DID.
   */
  public fun resolve(options: ResolveDidOptions?): DidResolutionResult = didWebApi.resolve(uri, options)

  /**
   * Default companion object for creating a [DidWebApi] with a default configuration.
   */
  public companion object Default : DidWebApi(DidWebApiConfiguration())
}

/**
 * Configuration options for the [DidWebApi].
 *
 * - [engine] is used to override the default ktor engine, which is [OkHttp].
 */
public class DidWebApiConfiguration internal constructor(
  public var engine: HttpClientEngine? = null,
)

/**
 * Returns a [DidWebApi] instance after applying [blockConfiguration].
 */
public fun DidWebApi(blockConfiguration: DidWebApiConfiguration.() -> Unit): DidWebApi {
  val conf = DidWebApiConfiguration().apply(blockConfiguration)
  return DidWebApiImpl(conf)
}

private class DidWebApiImpl(configuration: DidWebApiConfiguration) : DidWebApi(configuration)

private const val wellKnownURLPath = "/.well-known"
private const val didDocFilename = "/did.json"

/**
 * Implements [resolve] and [create] according to https://w3c-ccg.github.io/did-method-web/
 */
public sealed class DidWebApi(
  configuration: DidWebApiConfiguration
) : DidMethod<DidWeb, CreateDidOptions> {

  private val mapper = jacksonObjectMapper()

  private val engine: HttpClientEngine = configuration.engine ?: OkHttp.create {
    val appCache = Cache(File("cacheDir", "okhttpcache"), 10 * 1024 * 1024)
    val bootstrapClient = OkHttpClient.Builder().cache(appCache).build()

    val dns = DnsOverHttps.Builder().client(bootstrapClient)
      .url("https://dns.quad9.net/dns-query".toHttpUrl())
      .bootstrapDnsHosts(InetAddress.getByName("9.9.9.9"), InetAddress.getByName("149.112.112.112"))
      .build()

    val client = bootstrapClient.newBuilder().dns(dns).build()
    preconfigured = client
  }

  private val client = HttpClient(engine) {
    install(ContentNegotiation) {
      jackson { mapper }
    }
  }

  override val methodName: String = "web"

  override fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
    val parsedDid = try {
      DID.fromString(did)
    } catch (_: ParserException) {
      return DidResolutionResult(
        didResolutionMetadata = DidResolutionMetadata(
          error = ResolutionErrors.INVALID_DID.value,
        ),
      )
    }

    if (parsedDid.methodName != methodName) {
      return DidResolutionResult(
        didResolutionMetadata = DidResolutionMetadata(
          error = ResolutionErrors.METHOD_NOT_SUPPORTED.value,
        ),
      )
    }
    val docURL = getDocURL(parsedDid)

    val resp: HttpResponse = try {
      runBlocking {
        client.get(docURL) {
          contentType(ContentType.Application.Json)
        }
      }
    } catch (_: UnknownHostException) {
      return DidResolutionResult(
        didResolutionMetadata = DidResolutionMetadata(
          error = ResolutionErrors.NOT_FOUND.value,
        ),
      )
    }

    val body = runBlocking { resp.bodyAsText() }

    if (!resp.status.isSuccess()) {
      throw InvalidStatusException(resp.status.value, "resolution error response: '$body'")
    }
    return DidResolutionResult(
      didDocument = mapper.readValue(body, DIDDocument::class.java),
    )
  }

  override fun load(uri: String, keyManager: KeyManager): DidWeb {
    validateKeyMaterialInsideKeyManager(uri, keyManager)
    return DidWeb(uri, keyManager, this)
  }

  private fun getDocURL(parsedDid: DID): String {
    val domainNameWithPath = parsedDid.methodSpecificId.replace(":", "/")
    val decodedDomain = URLDecoder.decode(domainNameWithPath, UTF_8)

    val targetUrl = StringBuilder("https://$decodedDomain")

    val url = URL(targetUrl.toString())
    if (url.path.isEmpty()) {
      targetUrl.append(wellKnownURLPath)
    }
    targetUrl.append(didDocFilename)
    return targetUrl.toString()
  }

  public override fun create(keyManager: KeyManager, options: CreateDidOptions?): DidWeb {
    throw UnsupportedOperationException("Create operation is not supported for did:web")
  }
}