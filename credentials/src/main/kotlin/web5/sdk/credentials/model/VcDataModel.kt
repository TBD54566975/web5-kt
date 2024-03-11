package web5.sdk.credentials.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.net.URI
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

public const val DEFAULT_VC_CONTEXT: String = "https://www.w3.org/2018/credentials/v1"
public const val DEFAULT_VC_TYPE: String = "VerifiableCredential"

/**
 * Global date format used for formatting the issuance and expiration dates of credentials.
 * The value of the issuanceDate property MUST be a string value of an [XMLSCHEMA11-2] combined date-time
 */
private val DATE_FORMAT: SimpleDateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").apply {
  timeZone = TimeZone.getTimeZone("UTC")
}

private class DateSerializer : JsonSerializer<Date>() {
  override fun serialize(value: Date?, gen: JsonGenerator?, serializers: SerializerProvider?) {
    gen?.writeString(value?.let { DATE_FORMAT.format(it) })
  }
}

private class DateDeserializer : JsonDeserializer<Date>() {
  override fun deserialize(p: JsonParser?, ctxt: DeserializationContext?): Date {
    return DATE_FORMAT.parse(p?.text ?: "")
  }
}

private class CredentialSubjectSerializer : JsonSerializer<CredentialSubject>() {
  override fun serialize(value: CredentialSubject, gen: JsonGenerator, serializers: SerializerProvider) {
    gen.writeStartObject()
    // Write the id field. If id is null, write an empty string; otherwise, write its string representation.
    gen.writeStringField("id", value.id?.toString() ?: "")
    value.additionalClaims.forEach { (key, claimValue) ->
      gen.writeObjectField(key, claimValue)
    }
    gen.writeEndObject()
  }
}

private class CredentialSubjectDeserializer : JsonDeserializer<CredentialSubject>() {
  override fun deserialize(p: JsonParser, ctxt: DeserializationContext): CredentialSubject {
    val node: JsonNode = p.codec.readTree(p)
    val idNode = node.get("id")
    val id = idNode?.asText()?.takeIf { it.isNotBlank() }?.let { URI.create(it) }

    require(id.toString().isNotBlank()) {"Credential Subject id cannot be blank"}

    // Remove the "id" field and treat the rest as additionalClaims
    val additionalClaims = node.fields().asSequence().filterNot { it.key == "id" }
      .associate { it.key to it.value.asText() } // Assuming all values are stored as text

    return CredentialSubject.Builder()
      .id(id!!)
      .additionalClaims(additionalClaims)
      .build()
  }
}

private fun getObjectMapper(): ObjectMapper {
  return jacksonObjectMapper().apply {
    registerKotlinModule()
    setSerializationInclusion(JsonInclude.Include.NON_NULL)

    val dateModule = SimpleModule().apply {
      addSerializer(Date::class.java, DateSerializer())
      addDeserializer(Date::class.java, DateDeserializer())
      addSerializer(CredentialSubject::class.java, CredentialSubjectSerializer())
      addDeserializer(CredentialSubject::class.java, CredentialSubjectDeserializer())
    }
    registerModule(dateModule)
  }
}

/**
 * The [VcDataModel] instance representing the core data model of a verifiable credential.
 *
 * @see {@link https://www.w3.org/TR/vc-data-model/#credentials | VC Data Model}
 */
public class VcDataModel(
  public val id: URI?,
  @JsonProperty("@context")
  public val context: List<URI>,
  public val type: List<String>,
  public val issuer: URI,
  public val issuanceDate: Date,
  public val expirationDate: Date?,
  public val credentialSubject: CredentialSubject,
  public val credentialSchema: CredentialSchema?,
  public val credentialStatus: StatusList2021Entry?
) {
  /**
   * Builder class for creating [VcDataModel] instances.
   */
  public class Builder {
    private lateinit var id: URI
    private var context: List<URI> = listOf()
    private var type: List<String> = listOf()
    private lateinit var issuer: URI
    private lateinit var issuanceDate: Date
    private var expirationDate: Date? = null
    private lateinit var credentialSubject: CredentialSubject
    private var credentialSchema: CredentialSchema? = null
    private var credentialStatus: StatusList2021Entry? = null

    /**
     * Sets the ID URI for the [VcDataModel].
     * @param id The unique identifier URI of the credential.
     * @return Returns this builder to allow for chaining.
     */
    public fun id(id: URI): Builder = apply { this.id = id }

    /**
     * Sets the context URIs for the [VcDataModel].
     * @param context A list of context URIs.
     * @return Returns this builder to allow for chaining.
     */
    public fun context(context: List<URI>): Builder = apply { this.context = context }

    /**
     * Sets the type(s) for the [VcDataModel].
     * @param type A list of types.
     * @return Returns this builder to allow for chaining.
     */
    public fun type(type: List<String>): Builder = apply { this.type = type }

    /**
     * Sets the issuer URI for the [VcDataModel].
     * @param issuer The issuer URI of the credential.
     * @return Returns this builder to allow for chaining.
     */
    public fun issuer(issuer: URI): Builder = apply { this.issuer = issuer }

    /**
     * Sets the issuance date for the [VcDataModel].
     * @param issuanceDate The date when the credential was issued.
     * @return Returns this builder to allow for chaining.
     */
    public fun issuanceDate(issuanceDate: Date): Builder = apply { this.issuanceDate = issuanceDate }

    /**
     * Sets the expiration date for the [VcDataModel].
     * @param expirationDate The date when the credential expires.
     * @return Returns this builder to allow for chaining.
     */
    public fun expirationDate(expirationDate: Date?): Builder = apply { this.expirationDate = expirationDate }

    /**
     * Sets the credential subject for the [VcDataModel].
     * @param credentialSubject The subject of the credential.
     * @return Returns this builder to allow for chaining.
     */
    public fun credentialSubject(credentialSubject: CredentialSubject): Builder =
      apply { this.credentialSubject = credentialSubject }

    /**
     * Sets the credential schema for the [VcDataModel].
     * @param credentialSchema The schema of the credential.
     * @return Returns this builder to allow for chaining.
     */
    public fun credentialSchema(credentialSchema: CredentialSchema?): Builder =
      apply { this.credentialSchema = credentialSchema }

    /**
     * Sets the credential status for the [VcDataModel].
     * @param credentialStatus The status of the credential.
     * @return Returns this builder to allow for chaining.
     */
    public fun credentialStatus(credentialStatus: StatusList2021Entry?): Builder =
      apply { this.credentialStatus = credentialStatus }

    /**
     * Builds and returns the [VcDataModel] object.
     * @return The constructed [VcDataModel] object.
     * @throws IllegalStateException If the issuer or issuance date are not set, or other validation fails.
     */
    public fun build(): VcDataModel {

      require(context.contains(URI.create(DEFAULT_VC_CONTEXT))) { "context must include at least: $DEFAULT_VC_CONTEXT" }
      require(id.toString().isNotBlank()) { "ID URI cannot be blank" }
      require(type.contains(DEFAULT_VC_TYPE)) { "type must include at least: $DEFAULT_VC_TYPE" }
      require(issuer.toString().isNotBlank()) { "Issuer URI cannot be blank" }

      if (expirationDate != null) {
        require(issuanceDate.before(expirationDate)) { "Issuance date must be before expiration date" }
      }

      return VcDataModel(id, context, type, issuer, issuanceDate, expirationDate,
        credentialSubject, credentialSchema, credentialStatus)
    }
  }

  /**
   * Converts the [VcDataModel] instance to a JSON string.
   *
   * @return A JSON string representation of the [VcDataModel] instance.
   */
  public fun toJson(): String {
    val mapper = getObjectMapper()
    return mapper.writeValueAsString(this)
  }

  /**
   * Converts the [VcDataModel] instance into a Map representation.
   *
   * @return A Map containing key-value pairs representing the properties of the [VcDataModel] instance.
   */
  public fun toMap(): Map<String, Any> {
    val mapper = getObjectMapper()
    val jsonString = mapper.writeValueAsString(this)
    val typeRef = object : TypeReference<Map<String, Any>>() {}
    return mapper.readValue(jsonString, typeRef)
  }
  public companion object {

    /**
     * Parses a JSON string to create an instance of [VcDataModel].
     *
     * @param jsonString The JSON string representation of a [VcDataModel].
     * @return An instance of [VcDataModel].
     */
    public fun fromJsonObject(jsonString: String): VcDataModel {
      val mapper = getObjectMapper()
      return mapper.readValue(jsonString, object : TypeReference<VcDataModel>() {})
    }

    /**
     * Builds a new [CredentialSubject] instance from a map of properties.
     *
     * @param map A map representing the [CredentialSubject]'s properties.
     * @return An instance of [CredentialSubject] constructed from the provided map.
     */
    public fun fromMap(map: Map<String, Any>): VcDataModel {
      val mapper = getObjectMapper()
      val json = mapper.writeValueAsString(map)
      return mapper.readValue(json, VcDataModel::class.java)
    }
  }
}

/**
 * The [CredentialSubject] represents the value of the credentialSubject property as a set of objects containing
 * properties related to the subject of the verifiable credential.
 */
public class CredentialSubject(
  public val id: URI,
  public val additionalClaims: Map<String, Any>
) {
  /**
   * Builder class for creating [CredentialSubject] instances.
   */
  public class Builder {
    private lateinit var id: URI
    private var additionalClaims: Map<String, Any> = emptyMap()

    /**
     * Sets the ID URI for the credential subject.
     * @param id The unique identifier URI of the credential subject.
     * @return Returns this builder to allow for chaining.
     */
    public fun id(id: URI): Builder = apply { this.id = id }

    /**
     * Sets the additional claims for the credential subject.
     * Additional claims provide more information about the credential subject.
     * @param additionalClaims A map of claim names to claim values.
     * @return Returns this builder to allow for chaining.
     */
    public fun additionalClaims(additionalClaims: Map<String, Any>): Builder =
      apply { this.additionalClaims = additionalClaims }

    /**
     * Builds and returns the [CredentialSubject] object.
     * @return The constructed [CredentialSubject] object.
     * @throws IllegalStateException If the ID URI is not valid.
     */
    public fun build(): CredentialSubject {
      require(id.toString().isNotBlank()) { "ID URI cannot be blank" }

      return CredentialSubject(id, additionalClaims)
    }
  }
}


/**
 * The [CredentialSchema] Represents the schema defining the structure of a credential.
 */
public class CredentialSchema(
  public val id: String,
  public val type: String
) {
  /**
   * Builder class for creating [CredentialSchema] instances.
   */
  public class Builder {
    private lateinit var id: String
    private lateinit var type: String

    /**
     * Sets the ID for the credential schema.
     * @param id The unique identifier of the credential schema.
     * @return Returns this builder to allow for chaining.
     */
    public fun id(id: String): Builder = apply { this.id = id }

    /**
     * Sets the type for the credential schema.
     * @param type The type of the credential schema.
     * @return Returns this builder to allow for chaining.
     */
    public fun type(type: String): Builder = apply { this.type = type }

    /**
     * Builds and returns the [CredentialSchema] object.
     * @return The constructed [CredentialSchema] object.
     * @throws IllegalStateException If the id is not set.
     */
    public fun build(): CredentialSchema {
      require(id.toString().isNotBlank()) { "ID cannot be blank" }
      require(type == "JsonSchema") { "Type must be: JsonSchema" }

      return CredentialSchema(id, type)
    }
  }
}
