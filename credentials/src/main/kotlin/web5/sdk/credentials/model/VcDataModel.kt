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

/**
 * DateSerializer.
 */
private class DateSerializer : JsonSerializer<Date>() {
  override fun serialize(value: Date?, gen: JsonGenerator?, serializers: SerializerProvider?) {
    gen?.writeString(value?.let { DATE_FORMAT.format(it) })
  }
}

/**
 * DateDeserializer.
 */
private class DateDeserializer : JsonDeserializer<Date>() {
  override fun deserialize(p: JsonParser?, ctxt: DeserializationContext?): Date {
    return DATE_FORMAT.parse(p?.text ?: "")
  }
}

/**
 * CredentialSubjectSerializer.
 */
public class CredentialSubjectSerializer : JsonSerializer<CredentialSubject>() {
  override fun serialize(value: CredentialSubject, gen: JsonGenerator, serializers: SerializerProvider) {
    gen.writeStartObject()
    // Write the id field. If id is null, write an empty string; otherwise, write its string representation.
    gen.writeStringField("id", value.id?.toString() ?: "")
    // Write additional claims directly into the JSON object
    value.additionalClaims.forEach { (key, claimValue) ->
      gen.writeObjectField(key, claimValue)
    }
    gen.writeEndObject()
  }
}

/**
 * CredentialSubjectDeserializer.
 */
public class CredentialSubjectDeserializer : JsonDeserializer<CredentialSubject>() {
  override fun deserialize(p: JsonParser, ctxt: DeserializationContext): CredentialSubject {
    val node: JsonNode = p.codec.readTree(p)
    val idNode = node.get("id")
    val id = idNode?.asText()?.takeIf { it.isNotBlank() }?.let { URI.create(it) }

    // Remove the "id" field and treat the rest as additionalClaims
    val additionalClaims = node.fields().asSequence().filterNot { it.key == "id" }
      .associate { it.key to it.value.asText() } // Assuming all values are stored as text

    return CredentialSubject(id, additionalClaims)
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
  public val id: URI? = null,
  @JsonProperty("@context")
  public val context: MutableList<URI> = mutableListOf(),
  public val type: MutableList<String> = mutableListOf(),
  public val issuer: URI,
  public val issuanceDate: Date,
  public val expirationDate: Date? = null,
  public val credentialSubject: CredentialSubject,
  public val credentialSchema: CredentialSchema? = null,
  public val credentialStatus: BitstringStatusListEntry? = null
) {
  init {
    if(context.isEmpty() || context[0].toString() != DEFAULT_VC_CONTEXT) {
      context.add(0, URI.create(DEFAULT_VC_CONTEXT))
    }

    if(type.isEmpty() || type[0] != DEFAULT_VC_TYPE) {
      type.add(0, DEFAULT_VC_TYPE)
    }

    require(id == null || id.toString().isNotBlank()) { "ID URI cannot be blank" }
    require(issuer.toString().isNotBlank()) { "Issuer URI cannot be blank" }

    if (expirationDate != null) {
      require(issuanceDate.before(expirationDate)) { "Issuance date must be before expiration date" }
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
  public val id: URI? = null,
  public val additionalClaims: Map<String, Any> = emptyMap()
) {
  init {
    require(id == null || id.toString().isNotBlank()) { "ID URI cannot be blank" }
  }
}

/**
 * The [CredentialSchema] Represents the schema defining the structure of a credential.
 */
public class CredentialSchema(
  public val id: String,
  public val type: String? = null
) {
  init {
    require(type == null || type.isNotBlank()) { "Type cannot be blank" }
  }
}