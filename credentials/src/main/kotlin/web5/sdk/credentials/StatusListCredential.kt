package web5.sdk.credentials

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.ClientRequestException
import io.ktor.client.plugins.ResponseException
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import io.ktor.serialization.jackson.jackson
import kotlinx.coroutines.runBlocking
import web5.sdk.credentials.model.CredentialSubject
import web5.sdk.credentials.model.DEFAULT_STATUS_LIST_2021_ENTRY_TYPE
import web5.sdk.credentials.model.DEFAULT_STATUS_LIST_2021_VC_TYPE
import web5.sdk.credentials.model.DEFAULT_STATUS_LIST_CONTEXT
import web5.sdk.credentials.model.DEFAULT_VC_CONTEXT
import web5.sdk.credentials.model.DEFAULT_VC_TYPE
import web5.sdk.credentials.model.StatusList2021Entry
import web5.sdk.credentials.model.VcDataModel
import web5.sdk.dids.DidResolvers
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URI
import java.util.Base64
import java.util.BitSet
import java.util.Date
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * Status purpose of a status list credential or a credential with a credential status.
 */
public enum class StatusPurpose {
  REVOCATION,
  SUSPENSION
}

/**
 * The JSON property key for an encoded list.
 */
private const val ENCODED_LIST: String = "encodedList"

/**
 * The JSON property key for a status purpose.
 */
private const val STATUS_PURPOSE: String = "statusPurpose"

/**
 * The JSON property key for a type.
 */
private const val TYPE: String = "type"

/**
 * `StatusListCredential` represents a digitally verifiable status list credential according to the
 * [W3C Verifiable Credentials Status List v2021](https://www.w3.org/TR/vc-status-list/).
 *
 * When a status list is published, the result is a verifiable credential that encapsulates the status list.
 *
 */
public object StatusListCredential {
  /**
   * Create a [StatusListCredential] with a specific purpose, e.g., for revocation.
   *
   * @param statusListCredentialId The id used for the resolvable path to the status list credential [String].
   * @param issuer The issuer URI of the credential, as a [String].
   * @param statusPurpose The status purpose of the status list cred, eg: revocation, as a [StatusPurpose].
   * @param issuedCredentials The credentials to be included in the status list credential, eg: revoked credentials, list of type [VerifiableCredential].
   * @return A [VerifiableCredential] instance.
   * @throws StatusListCredentialCreateException If the status list credential cannot be created.
   * Example:
   * ```
   * val statusListCredential = StatusListCredential.create("http://example.com/statuslistcred/id123", "http://example.com/issuers/1", StatusPurpose.REVOCATION, listOf(vc1,vc2))
   * ```
   */
  @Throws(StatusListCredentialCreateException::class)
  public fun create(
    statusListCredentialId: String,
    issuer: String,
    statusPurpose: StatusPurpose,
    issuedCredentials: Iterable<VerifiableCredential>
  ): VerifiableCredential {
    val statusListIndexes: List<String>
    val bitString: String

    try {
      statusListIndexes = prepareCredentialsForStatusList(statusPurpose, issuedCredentials)
      bitString = bitstringGeneration(statusListIndexes)
    } catch (e: Exception) {
      throw StatusListCredentialCreateException(e, "Failed to create status list credential: ${e.message}")
    }

    try {
      URI.create(statusListCredentialId)
    } catch (e: Exception) {
      throw IllegalArgumentException("status list credential id is not a valid URI", e)
    }

    try {
      URI.create(issuer)
    } catch (e: Exception) {
      throw IllegalArgumentException("issuer is not a valid URI", e)
    }

    try {
      DidResolvers.resolve(issuer)
    } catch (e: Exception) {
      throw IllegalArgumentException("issuer: $issuer not resolvable", e)
    }

    val claims = mapOf(TYPE to DEFAULT_STATUS_LIST_2021_ENTRY_TYPE,
      STATUS_PURPOSE to statusPurpose.toString().lowercase(),
      ENCODED_LIST to bitString)

    val credSubject = CredentialSubject.Builder()
      .id(URI.create(statusListCredentialId))
      .additionalClaims(claims)
      .build()

    val vcDataModel = VcDataModel.Builder()
      .id(URI.create(statusListCredentialId))
      .context(mutableListOf(URI.create(DEFAULT_VC_CONTEXT), URI.create(DEFAULT_STATUS_LIST_CONTEXT)))
      .type(mutableListOf(DEFAULT_VC_TYPE, DEFAULT_STATUS_LIST_2021_VC_TYPE))
      .issuer(URI.create(issuer))
      .issuanceDate(Date())
      .credentialSubject(credSubject)
      .build()

    return VerifiableCredential(vcDataModel)
  }

  /**
   * Validates if a given credential is part of the status list represented by a [VerifiableCredential].
   *
   * @param credentialToValidate The [VerifiableCredential] to be validated against the status list.
   * @param statusListCredential The [VerifiableCredential] representing the status list.
   * @return A [Boolean] indicating whether the `credentialToValidate` is part of the status list.
   *
   * This function checks if the given `credentialToValidate`'s status list index is present in the expanded status list derived from the `statusListCredential`.
   *
   * Example:
   * ```
   * val isRevoked = validateCredentialInStatusList(credentialToCheck, statusListCred)
   * ```
   */
  public fun validateCredentialInStatusList(
    credentialToValidate: VerifiableCredential,
    statusListCredential: VerifiableCredential
  ): Boolean {
    val statusListEntryValue: StatusList2021Entry =
      StatusList2021Entry.fromJsonObject(credentialToValidate.vcDataModel.credentialStatus!!.toJson())

    val credentialSubject = statusListCredential.vcDataModel.credentialSubject

    val statusListCredStatusPurpose: String? = credentialSubject.additionalClaims[STATUS_PURPOSE] as? String?

    require(statusListEntryValue.statusPurpose != null) {
      "Status purpose in the credential to validate is null"
    }

    require(statusListCredStatusPurpose != null) {
      "Status purpose in the status list credential is null"
    }

    require(statusListEntryValue.statusPurpose == statusListCredStatusPurpose) {
      "Status purposes do not match between the credentials"
    }

    val compressedBitstring: String? =
      credentialSubject.additionalClaims[ENCODED_LIST] as? String?

    require(!compressedBitstring.isNullOrEmpty()) {
      "Compressed bitstring is null or empty"
    }

    val credentialIndex = statusListEntryValue.statusListIndex
    val expandedValues: List<String> = bitstringExpansion(compressedBitstring)

    return expandedValues.any { it == credentialIndex }
  }


  /**
   * Validates if a given credential is part of the status list.
   *
   * @param credentialToValidate The [VerifiableCredential] to be validated against the status list.
   * @param httpClient An optional [HttpClient] for fetching the status list credential. If not provided, a default HTTP client will be used.
   * @return A [Boolean] indicating whether the `credentialToValidate` is part of the status list.
   * @throws StatusListCredentialFetchException If the status list credential cannot be fetched.
   * @throws StatusListCredentialParseException If the status list credential cannot be parsed.
   *
   * This function fetches the status list credential from a URL present in the `credentialToValidate`.
   * It supports using either a user-provided `httpClient` or a default client when no client is passed in.
   * The function then checks if the given `credentialToValidate`'s status list index is present in the expanded status list derived from the fetched status list credential.
   *
   * Example:
   * ```
   * val isRevoked = validateCredentialInStatusList(credentialToCheck)
   * ```
   */
  @JvmOverloads
  @Throws(StatusListCredentialFetchException::class, StatusListCredentialParseException::class)
  public fun validateCredentialInStatusList(
    credentialToValidate: VerifiableCredential,
    httpClient: HttpClient? = null // default HTTP client but can be overridden
  ): Boolean {
    return runBlocking {
      var isDefaultClient = false
      val client = httpClient ?: defaultHttpClient().also { isDefaultClient = true }

      try {
        val statusListEntryValue: StatusList2021Entry =
          StatusList2021Entry.fromJsonObject(credentialToValidate.vcDataModel.credentialStatus!!.toJson())
        val statusListCredential =
          client.fetchStatusListCredential(statusListEntryValue.statusListCredential.toString())

        return@runBlocking validateCredentialInStatusList(credentialToValidate, statusListCredential)
      } finally {
        if (isDefaultClient) {
          client.close()
        }
      }
    }
  }

  private fun defaultHttpClient(): HttpClient {
    return HttpClient(OkHttp) {
      install(ContentNegotiation) {
        jackson { jacksonObjectMapper() }
      }
    }
  }

  private suspend fun HttpClient.fetchStatusListCredential(url: String): VerifiableCredential {
    try {
      val response: HttpResponse = this.get(url)
      if (response.status.isSuccess()) {
        val body = response.bodyAsText()
        return VerifiableCredential.parseJwt(body)
      } else {
        throw ClientRequestException(
          response,
          "Failed to retrieve VerifiableCredentialType from $url"
        )
      }
    } catch (e: ResponseException) {
      // ClientRequestException will be caught here since it is a subclass of ResponseException
      throw StatusListCredentialFetchException(e, "Failed to fetch status list credential: ${e.message}")
    } catch (e: IllegalArgumentException) {
      throw StatusListCredentialParseException(e, "Failed to parse status list credential: ${e.message}")
    }
  }

  /**
   * Prepares a list of credentials for status list processing.
   *
   * This function:
   * - Ensures all provided credentials use the `StatusList2021` format for their status.
   * - Validates that all credentials use the `StatusList2021` in the `credentialStatus` property.
   * - Assembles a list of `statusListIndex` values for the bitstring generation algorithm.
   */
  private fun prepareCredentialsForStatusList(
    statusPurpose: StatusPurpose,
    credentials: Iterable<VerifiableCredential>
  ): List<String> {
    val duplicateSet = mutableSetOf<String>()
    for (vc in credentials) {
      requireNotNull(vc.vcDataModel.credentialStatus) { "no credential status found in credential" }

      val statusListEntry: StatusList2021Entry =
        StatusList2021Entry.fromJsonObject(vc.vcDataModel.credentialStatus.toJson())

      require(statusListEntry.statusPurpose == statusPurpose.toString().lowercase()) {
        "status purpose mismatch"
      }

      if (!duplicateSet.add(statusListEntry.statusListIndex)) {
        throw IllegalArgumentException("duplicate entry found with index: ${statusListEntry.statusListIndex}")
      }
    }

    return duplicateSet.toList()
  }

  /**
   * Generates a compressed bitstring representation of the provided status list indexes.
   *
   * This function performs the following steps:
   * 1. Initializes a list of bits with a minimum size of 16KB, where each bit is set to 0.
   * 2. Iterates through the provided status list indexes, and for each index:
   *    - Validates its value.
   *    - Sets the corresponding bit in the bitstring to 1.
   * 3. Compresses the generated bitstring using the GZIP compression algorithm.
   * 4. Returns the base64-encoded representation of the compressed bitstring.
   */
  private fun bitstringGeneration(statusListIndexes: List<String>): String {
    val duplicateCheck = mutableSetOf<Int>()

    // 1. Let bitstring be a list of bits with a minimum size of 16KB, where each bit is initialized to 0 (zero).
    val bitSetSize = 16 * 1024 * 8
    val bitSet = BitSet(bitSetSize)

    for (index in statusListIndexes) {
      val indexInt = index.toIntOrNull()

      require(indexInt != null && indexInt >= 0) {
        "invalid status list index: $index"
      }

      require(indexInt < bitSetSize) {
        throw IndexOutOfBoundsException("invalid status list index: $index, index is larger than the bitset size")
      }

      require(duplicateCheck.add(indexInt)) {
        "duplicate status list index value found: $indexInt"
      }

      bitSet.set(indexInt)
    }

    val bitstringBinary = bitSet.toByteArray()
    val baos = ByteArrayOutputStream()
    GZIPOutputStream(baos).use { it.write(bitstringBinary) }
    return Base64.getEncoder().encodeToString(baos.toByteArray())
  }

  /**
   * Expands a compressed bitstring and produces a list of indices where the bit is set to 1.
   *
   * This function performs the following steps:
   * 1. Decodes the provided compressed bitstring from its base64 representation.
   * 2. Decompresses the decoded bitstring using the GZIP compression algorithm.
   * 3. Iterates through the decompressed bitstring and collects the indices of bits set to 1.
   * @param compressedBitstring base64 encoded and compressed bitstring to decode and expand.
   * @return A list of indices where the bit is set to 1 (i.e. the status list indexes).
   * @throws BitstringExpansionException if the bitstring cannot be decoded or expanded.
   */
  @Throws(BitstringExpansionException::class)
  private fun bitstringExpansion(compressedBitstring: String): List<String> {
    val decoded: ByteArray
    try {
      decoded = Base64.getDecoder().decode(compressedBitstring)
    } catch (e: Exception) {
      throw BitstringExpansionException(e, "Failed to decode compressed bitstring: ${e.message}")
    }

    val bitstringInputStream = ByteArrayInputStream(decoded)
    val byteArrayOutputStream = ByteArrayOutputStream()

    try {
      GZIPInputStream(bitstringInputStream).use { it.copyTo(byteArrayOutputStream) }
    } catch (e: Exception) {
      throw BitstringExpansionException(e, "Failed to unzip status list bitstring using GZIP: ${e.message}")
    }

    val unzipped = byteArrayOutputStream.toByteArray()
    val b = BitSet.valueOf(unzipped)

    val expanded = mutableListOf<String>()
    for (i in 0 until b.length()) {
      if (b[i]) expanded.add(i.toString())
    }

    return expanded
  }
}