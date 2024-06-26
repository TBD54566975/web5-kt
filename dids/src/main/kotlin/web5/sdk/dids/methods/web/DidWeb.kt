package web5.sdk.dids.methods.web

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.ResponseException
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.HttpResponse
import io.ktor.http.contentType
import io.ktor.http.ContentType
import io.ktor.http.isSuccess
import io.ktor.serialization.jackson.jackson
import kotlinx.coroutines.runBlocking
import okhttp3.Cache
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.dnsoverhttps.DnsOverHttps
import web5.sdk.common.Json
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.didcore.DidDocument
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.exceptions.ParserException
import web5.sdk.dids.ResolutionError
import web5.sdk.dids.did.BearerDid
import web5.sdk.dids.did.PortableDid
import java.io.File
import java.net.InetAddress
import java.net.URL
import java.net.URLDecoder
import java.net.UnknownHostException
import kotlin.text.Charsets.UTF_8

/**
 * Provides a specific implementation for creating "did:web" method Decentralized Identifiers (DIDs).
 *
 * A "did:web" DID is an implementation that uses the web domains existing reputation system. More details can be
 * read in https://w3c-ccg.github.io/did-method-web/
 *
 * DidWeb API does not support creating DIDs, only resolving them.
 *
 * ### Usage Example:
 * ```kotlin
 * val keyManager = InMemoryKeyManager()
 * val did = DidWeb.resolve("did:web:tbd.website")
 * ```
 */
public class DidWeb {

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
  val config = DidWebApiConfiguration().apply(blockConfiguration)
  return DidWebApiImpl(config)
}

private class DidWebApiImpl(configuration: DidWebApiConfiguration) : DidWebApi(configuration)

private const val WELL_KNOWN_URL_PATH = "/.well-known"
private const val DID_DOC_FILE_NAME = "/did.json"

/**
 * Implements [resolve] according to https://w3c-ccg.github.io/did-method-web/
 */
public sealed class DidWebApi(
  configuration: DidWebApiConfiguration
) {
  public val methodName: String = "web"

  private val logger = KotlinLogging.logger {}

  private val mapper = Json.jsonMapper

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

  /**
   * Resolves a `did:jwk` URI into a [DidResolutionResult].
   *   
   * This method parses the provided `did` URI to extract the Jwk information.
   * It validates the method of the DID URI and then attempts to parse the
   * Jwk from the URI. If successful, it constructs a [DidDocument] with the
   * resolved Jwk, generating a [DidResolutionResult].
   *   
   * The method ensures that the DID URI adheres to the `did:jwk` method
   * specification and handles exceptions that may arise during the parsing
   * and resolution process.
   *   
   * @param did did URI to parse
   * @return [DidResolutionResult] containing the resolved DID document.
   * If the DID URI is invalid, not conforming to the `did:jwk` method, or
   * if any other error occurs during the resolution process, it returns
   * an invalid [DidResolutionResult].
   */
  public fun resolve(did: String): DidResolutionResult {
    return try {
      resolveInternal(did)
    } catch (e: Exception) {
      logger.warn(e) { "resolving DID $did failed, ${e.message}" }
      DidResolutionResult.fromResolutionError(ResolutionError.INTERNAL_ERROR)
    }
  }

  /**
   * Instantiates a [BearerDid] object for the DID WEB method from a given [PortableDid].
   *
   * This method allows for the creation of a `BearerDid` object using a previously created DID's
   * key material, DID document, and metadata.
   *
   * @param portableDid - The PortableDid object to import.
   * @param keyManager - Optionally specify an external Key Management System (KMS) used to
   *                            generate keys and sign data. If not given, a new
   *                            [InMemoryKeyManager] instance will be created and
   *                            used.
   * @returns a BearerDid object representing the DID formed from the
   *          provided PortableDid.
   */
  @JvmOverloads
  public fun import(portableDid: PortableDid, keyManager: KeyManager = InMemoryKeyManager()): BearerDid {
    return BearerDid.import(portableDid, keyManager)
  }

  private fun resolveInternal(did: String): DidResolutionResult {
    val parsedDid = try {
      Did.parse(did)
    } catch (_: ParserException) {
      return DidResolutionResult.fromResolutionError(ResolutionError.INVALID_DID)
    }

    if (parsedDid.method != methodName) {
      return DidResolutionResult.fromResolutionError(ResolutionError.METHOD_NOT_SUPPORTED)
    }
    val docURL = decodeId(parsedDid)

    val resp: HttpResponse = try {
      runBlocking {
        client.get(docURL) {
          contentType(ContentType.Application.Json)
        }
      }
    } catch (e: UnknownHostException) {
      logger.warn(e) { "failed to make GET request to $did doc URL, ${e.message}" }
      return DidResolutionResult.fromResolutionError(ResolutionError.NOT_FOUND)
    }

    val body = runBlocking { resp.bodyAsText() }

    if (!resp.status.isSuccess()) {
      throw ResponseException(resp, "resolution error response: '$body'")
    }
    return DidResolutionResult(
      didDocument = mapper.readValue(body, DidDocument::class.java),
    )
  }

  private fun decodeId(parsedDid: Did): String {
    val domainNameWithPath = parsedDid.id.replace(":", "/")
    val decodedDomain = URLDecoder.decode(domainNameWithPath, UTF_8)
    val protocol = if (LocalHostDomainMatcher.isLocalHostDomain(decodedDomain)) "http://" else "https://"
    val targetUrl = StringBuilder("$protocol$decodedDomain")

    val url = URL(targetUrl.toString())
    if (url.path.isEmpty()) {
      targetUrl.append(WELL_KNOWN_URL_PATH)
    }
    targetUrl.append(DID_DOC_FILE_NAME)

    return targetUrl.toString()
  }
}