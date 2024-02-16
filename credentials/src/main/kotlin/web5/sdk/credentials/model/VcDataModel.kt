package web5.sdk.credentials.model

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.net.URI
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

/**
 * Global date format used for formatting the issuance and expiration dates of credentials.
 * The value of the issuanceDate property MUST be a string value of an [XMLSCHEMA11-2] combined date-time
 */
public val DATE_FORMAT: SimpleDateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").apply {
  timeZone = TimeZone.getTimeZone("UTC")
}

/**
 * The [VcDataModel] instance representing the core data model of a verifiable credential.
 *
 * @see {@link https://www.w3.org/TR/vc-data-model/#credentials | VC Data Model}
 */
public data class VcDataModel(
  val id: URI? = null,
  val context: List<URI>,
  val type: List<String>,
  val issuer: URI,
  val issuanceDate: Date,
  val expirationDate: Date? = null,
  val credentialSubject: CredentialSubject,
  val credentialSchema: CredentialSchema? = null,
  val credentialStatus: BitstringStatusListEntry? = null,
) {

  /**
   * Vc Data Model Builder.
   */
  public class Builder {
    private var id: URI? = null
    private var context: List<URI> = listOf()
    private var type: List<String> = listOf()
    private var issuer: URI? = null
    private var issuanceDate: Date? = null
    private var expirationDate: Date? = null
    private var credentialSubject: CredentialSubject? = null
    private var credentialSchema: CredentialSchema? = null
    private var credentialStatus: BitstringStatusListEntry? = null

    /**
     * Sets the identifier of the credential.
     *
     * @param id The unique identifier for the credential as a [URI].
     * @return The current instance of [Builder] for chaining.
     */
    public fun id(id: URI): Builder = apply { this.id = id }

    /**
     * Sets the context(s) of the credential.
     *
     * @param contexts A list of [URI]s that establish the context of the credential.
     * @return The current instance of [Builder] for chaining.
     */
    public fun contexts(contexts: List<URI>): Builder = apply { this.context = contexts }

    /**
     * Sets the type(s) of the credential.
     *
     * @param type A list of strings that specify the type of credential being offered.
     * @return The current instance of [Builder] for chaining.
     */
    public fun type(type: List<String>): Builder = apply { this.type = type }

    /**
     * Sets the issuer of the credential.
     *
     * @param issuer The [URI] identifying the entity that issued the credential.
     * @return The current instance of [Builder] for chaining.
     */
    public fun issuer(issuer: URI): Builder = apply { this.issuer = issuer }

    /**
     * Sets the issuance date of the credential.
     *
     * @param issuanceDate The date when the credential was issued.
     * @return The current instance of [Builder] for chaining.
     */
    public fun issuanceDate(issuanceDate: Date): Builder = apply { this.issuanceDate = issuanceDate }

    /**
     * Sets the expiration date of the credential.
     *
     * @param expirationDate The date when the credential expires.
     * @return The current instance of [Builder] for chaining.
     */
    public fun expirationDate(expirationDate: Date): Builder = apply { this.expirationDate = expirationDate }

    /**
     * Sets the subject of the credential.
     *
     * @param credentialSubject The [CredentialSubject] that the credential is about.
     * @return The current instance of [Builder] for chaining.
     */
    public fun credentialSubject(credentialSubject: CredentialSubject): Builder =
      apply { this.credentialSubject = credentialSubject }

    /**
     * Sets the schema of the credential.
     *
     * @param credentialSchema The [CredentialSchema] that defines the structure of the credential. Can be null.
     * @return The current instance of [Builder] for chaining.
     */
    public fun credentialSchema(credentialSchema: CredentialSchema?): Builder =
      apply { this.credentialSchema = credentialSchema }

    /**
     * Sets the status of the credential.
     *
     * @param credentialStatus The [BitstringStatusListEntry] representing the status of the credential. Can be null.
     * @return The current instance of [Builder] for chaining.
     */
    public fun credentialStatus(credentialStatus: BitstringStatusListEntry?): Builder =
      apply { this.credentialStatus = credentialStatus }


    /**
     * Constructs a [VcDataModel] instance with the current state of the builder.
     *
     * @return A fully constructed [VcDataModel] instance.
     * @throws IllegalArgumentException If required fields (issuer, issuanceDate, credentialSubject) are not set.
     */
    public fun build(): VcDataModel {
      require(issuer != null) { "Issuer must be set" }
      require(issuanceDate != null) { "IssuanceDate must be set" }
      require(credentialSubject != null) { "CredentialSubject must be set" }

      return VcDataModel(
        id,
        context,
        type,
        issuer!!,
        issuanceDate!!,
        expirationDate,
        credentialSubject!!,
        credentialSchema,
        credentialStatus,
      )
    }
  }

  /**
   * Converts the [VcDataModel] instance to a JSON string.
   *
   * @return A JSON string representation of the [VcDataModel] instance.
   */
  public fun toJson(): String {
    val mapper = jacksonObjectMapper()
    return mapper.writeValueAsString(this)
  }


  /**
   * Converts the [VcDataModel] instance into a Map representation.
   *
   * @return A Map containing key-value pairs representing the properties of the [VcDataModel] instance.
   */
  public fun toMap(): Map<String, Any> = mutableMapOf<String, Any>().apply {
    id?.also { put("id", it.toString()) }
    put("@context", context.map { uri -> uri.toString() })
    put("type", type)
    put("issuer", issuer.toString())
    put("issuanceDate", DATE_FORMAT.format(issuanceDate))
    expirationDate?.also { put("expirationDate", DATE_FORMAT.format(it)) }
    put("credentialSubject", credentialSubject.toMap())
    credentialSchema?.also { put("credentialSchema", it.toMap()) }
    credentialStatus?.also { put("credentialStatus", it.toMap()) }
  }

  public companion object {
    /**
     * Builds a new [CredentialSubject] instance from a map of properties.
     *
     * @param map A map representing the [CredentialSubject]'s properties.
     * @return An instance of [CredentialSubject] constructed from the provided map.
     */
    public fun fromMap(map: Map<String, Any>): VcDataModel {
      require(map.containsKey("issuer")) { "Issuer is required" }
      require(map.containsKey("issuanceDate")) { "IssuanceDate is required" }
      require(map.containsKey("credentialSubject")) { "CredentialSubject is required" }

      return VcDataModel(
        id = (map["id"] as? String)?.let { URI.create(it) },
        context = (map["@context"] as? List<*>)?.mapNotNull {
          (it as? String)?.let { str -> URI.create(str) }
        } ?: listOf(),
        type = map["type"] as? List<String> ?: listOf(),
        issuer = URI.create(map["issuer"] as String),
        issuanceDate = DATE_FORMAT.parse(map["issuanceDate"] as String),
        expirationDate = (map["expirationDate"] as? String)?.let { DATE_FORMAT.parse(it) },
        credentialSubject = CredentialSubject.fromMap(map["credentialSubject"] as Map<String, Any>),
        credentialSchema = (map["credentialSchema"] as? Map<String, Any>)?.let { CredentialSchema.fromMap(it) },
        credentialStatus = (map["credentialStatus"] as? Map<String, Any>)?.let { BitstringStatusListEntry.fromMap(it) }
      )
    }

    /**
     * Parses a JSON string to create an instance of [VcDataModel].
     *
     * @param jsonString The JSON string representation of a [VcDataModel].
     * @return An instance of [VcDataModel].
     */
    public fun fromJsonObject(jsonString: String): VcDataModel {
      val mapper = jacksonObjectMapper()
      return mapper.readValue(jsonString, object : TypeReference<VcDataModel>() {})
    }
  }
}

/**
 * The [CredentialSubject] represents the value of the credentialSubject property as a set of objects containing
 * properties related to the subject of the verifiable credential.
 */
public data class CredentialSubject(
  val id: URI? = null,
  val additionalClaims: Map<String, Any> = emptyMap()
) {

  /**
   * Builder for [CredentialSubject].
   */
  public class Builder {
    private var id: URI? = null
    private var additionalClaims: Map<String, Any> = emptyMap()

    /**
     * Sets the identifier of the credential subject.
     *
     * @param id The unique identifier for the credential subject as a [URI].
     * @return The current instance of [Builder] for chaining.
     */
    public fun id(id: URI): Builder = apply { this.id = id }

    /**
     * Sets additional claims of the credential subject.
     *
     * @param claims A map of additional claims with string keys and any type of values.
     * @return The current instance of [Builder] for chaining.
     */
    public fun claims(claims: Map<String, Any>): Builder = apply { this.additionalClaims = claims }

    /**
     * Constructs a [CredentialSubject] instance with the current state of the builder.
     *
     * @return A fully constructed [CredentialSubject] instance.
     */
    public fun build(): CredentialSubject = CredentialSubject(id, additionalClaims)
  }

  /**
   * Converts the [CredentialSubject] instance to a JSON string.
   *
   * @return A JSON string representation of the [CredentialSubject] instance.
   */
  public fun toJson(): String {
    val mapper = jacksonObjectMapper()
    return mapper.writeValueAsString(this)
  }

  /**
   * Converts the [CredentialSubject] instance into a Map representation.
   *
   * @return A Map containing key-value pairs representing the properties of the [CredentialSubject] instance.
   */
  public fun toMap(): Map<String, Any> = mapOf<String, Any>("id" to (id?.toString() ?: "")).plus(additionalClaims)

  public companion object {
    /**
     * Converts a map representation into an instance of [CredentialSubject].
     *
     * @param map A map containing the properties of a [CredentialSubject].
     * @return An instance of [CredentialSubject].
     */
    public fun fromMap(map: Map<String, Any>): CredentialSubject {
      val id = (map["id"] as? String)?.let { URI.create(it) }
      val additionalClaims = map.filterKeys { it != "id" }
      return CredentialSubject(id, additionalClaims)
    }
  }
}

/**
 * The [CredentialSchema] Represents the schema defining the structure of a credential.
 */
public data class CredentialSchema(
  val id: String,
  val type: String? = null
) {
  /**
   * Converts the [CredentialSchema] instance into a Map representation.
   *
   * @return A Map containing key-value pairs representing the properties of the [CredentialSchema] instance.
   */
  public fun toMap(): Map<String, Any> = mapOf("id" to id).let { map ->
    type?.let { map.plus("type" to it) } ?: map
  }

  public companion object {
    /**
     * Converts a map representation into an instance of [CredentialSchema].
     *
     * @param map A map containing the properties of a [CredentialSchema].
     * @return An instance of [CredentialSchema].
     */
    public fun fromMap(map: Map<String, Any>): CredentialSchema {
      val id = map["id"] as? String ?: throw IllegalArgumentException("CredentialSchema id is required")
      val type = map["type"] as? String
      return CredentialSchema(id, type)
    }
  }
}

/**
 * BitstringStatusListEntry.
 */
public data class BitstringStatusListEntry(
  val id: URI,
  val type: String,
  val statusListIndex: String,
  val statusListCredential: URI,
  val statusPurpose: String,
) {

  /**
   * BitstringStatusListEntry Builder.
   */
  public class Builder {
    private var id: URI? = null
    private var type: String? = null
    private var statusListIndex: String? = null
    private var statusListCredential: URI? = null
    private var statusPurpose: String? = null

    /**
     * Sets the unique identifier of the object being built.
     *
     * @param id The URI representing the unique identifier. This is a mandatory parameter for constructing the object.
     * @return The builder instance for chaining further configuration calls.
     */
    public fun id(id: URI): Builder = apply { this.id = id }

    /**
     * Sets the type of the object being built. The type is a string that categorizes or specifies the object's nature within its domain.
     *
     * @param type A string representing the type of the object. This parameter helps in defining the object's classification.
     * @return The builder instance for chaining further configuration calls.
     */
    public fun type(type: String): Builder = apply{ this.type = type }

    /**
     * Sets the index of the status list for the object being built. The status list index is a string that specifies the position or identifier within a status list.
     *
     * @param statusListIndex A string representing the index within a status list. This is used to reference or locate the object's status in a predefined list.
     * @return The builder instance for chaining further configuration calls.
     */
    public fun statusListIndex(statusListIndex: String): Builder = apply { this.statusListIndex = statusListIndex }

    /**
     * Sets the credential of the status list for the object being built. The status list credential is a URI that points to a credential or certificate supporting the object's status.
     *
     * @param statusListCredential The URI pointing to the credential or certificate. This provides a verifiable link to the object's status accreditation.
     * @return The builder instance for chaining further configuration calls.
     */
    public fun statusListCredential(statusListCredential: URI): Builder =
      apply { this.statusListCredential = statusListCredential }

    /**
     * Sets the purpose of the status for the object being built. The status purpose is a string that explains why the status is assigned or its role.
     *
     * @param statusPurpose A string detailing the reason behind the object's status. This clarifies the context or intention of the assigned status.
     * @return The builder instance for chaining further configuration calls.
     */
    public fun statusPurpose(statusPurpose: String): Builder = apply { this.statusPurpose = statusPurpose }

    /**
     * Constructs a [BitstringStatusListEntry] instance with the current state of the builder.
     *
     * @return A fully constructed [BitstringStatusListEntry] instance.
     * @throws IllegalArgumentException If required fields (id, type, statusListIndex, statusListCredential, statusPurpose) are not set.
     */
    public fun build(): BitstringStatusListEntry {
      require(id != null) { "id must be set" }
      require(statusListIndex != null) { "statusListIndex must be set" }
      require(statusListCredential != null) { "statusListCredential must be set" }
      require(statusPurpose != null) { "statusPurpose must be set" }

      return BitstringStatusListEntry(
        id!!,
        type ?: "BitstringStatusListEntry", // Assuming type can have a default value
        statusListIndex!!,
        statusListCredential!!,
        statusPurpose!!
      )
    }
  }

  /**
   * Converts the [BitstringStatusListEntry] instance to a JSON string.
   *
   * @return A JSON string representation of the [BitstringStatusListEntry] instance.
   */
  public fun toJson(): String {
    val mapper = jacksonObjectMapper()
    return mapper.writeValueAsString(this)
  }


  /**
   * Converts the [BitstringStatusListEntry] instance into a Map representation.
   *
   * @return A Map containing key-value pairs representing the properties of the [BitstringStatusListEntry] instance.
   */
  public fun toMap(): Map<String, Any> {
    return mapOf(
      "id" to id.toString(),
      "type" to type,
      "statusListIndex" to statusListIndex,
      "statusListCredential" to statusListCredential.toString(),
      "statusPurpose" to statusPurpose
    )
  }

  public companion object {
    /**
     * Creates an instance of [BitstringStatusListEntry] from a map of its properties.
     *
     * @param map A map containing the properties of a [BitstringStatusListEntry].
     * @return An instance of [BitstringStatusListEntry].
     * @throws IllegalArgumentException If required properties are missing.
     */
    public fun fromMap(map: Map<String, Any>): BitstringStatusListEntry {
      // Check for required properties and throw IllegalArgumentException if any are missing
      require(map.containsKey("id") && map["id"] is String) { "id is required" }
      require(map.containsKey("type") && map["type"] is String) { "type is required" }
      require(map.containsKey("statusListIndex") && map["statusListIndex"] is String) {
        "statusListIndex is required"
      }
      require(map.containsKey("statusListCredential") && map["statusListCredential"] is String) {
        "statusListCredential is required"
      }
      require(map.containsKey("statusPurpose") && map["statusPurpose"] is String) { "statusPurpose is required" }


      return BitstringStatusListEntry(
        id = URI.create(map["id"] as String),
        type = map["type"] as String,
        statusListIndex = map["statusListIndex"] as String,
        statusListCredential = URI.create(map["statusListCredential"] as String),
        statusPurpose = map["statusPurpose"] as String
      )
    }


    /**
     * Parses a JSON string to create an instance of [BitstringStatusListEntry].
     *
     * @param jsonString The JSON string representation of a [BitstringStatusListEntry].
     * @return An instance of [BitstringStatusListEntry].
     */
    public fun fromJsonObject(jsonString: String): BitstringStatusListEntry {
      val mapper = jacksonObjectMapper()
      return mapper.readValue(jsonString, object : TypeReference<BitstringStatusListEntry>() {})
    }
  }
}