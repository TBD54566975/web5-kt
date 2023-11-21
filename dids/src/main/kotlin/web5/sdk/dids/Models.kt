package web5.sdk.dids

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonValue
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.nimbusds.jose.jwk.JWK

/**
 * Enum representing the purpose of a public key.
 */
public enum class PublicKeyPurpose(@get:JsonValue public val code: String) {
  AUTHENTICATION("authentication"),
  KEY_AGREEMENT("keyAgreement"),
  ASSERTION_METHOD("assertionMethod"),
  CAPABILITY_DELEGATION("capabilityDelegation"),
  CAPABILITY_INVOCATION("capabilityInvocation"),
}

/**
 * Represents a public key in the ION document as defined in item 3 of https://identity.foundation/sidetree/spec/#add-public-keys
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public data class PublicKey(
  public val id: String,
  public val type: String,
  public val controller: String? = null,

  @JsonSerialize(using = JacksonJwk.Serializer::class)
  @JsonDeserialize(using = JacksonJwk.Deserializer::class)
  public val publicKeyJwk: JWK,
  public val purposes: Iterable<PublicKeyPurpose> = emptyList()
)

/**
 * JacksonJWK is a utility class that facilitates serialization for [JWK] types, so that it's easy to integrate with any
 * class that is meant to be serialized to/from JSON.
 */
public class JacksonJwk {
  /**
   * [Serializer] implements [JsonSerializer] for use with the [JsonSerialize] annotation from Jackson.
   */
  public object Serializer : JsonSerializer<JWK>() {
    override fun serialize(value: JWK, gen: JsonGenerator, serializers: SerializerProvider) {
      with(gen) {
        writeObject(value.toJSONObject())
      }
    }
  }

  /**
   * [Deserializer] implements [JsonDeserializer] for use with the [JsonDeserialize] annotation from Jackson.
   */
  public object Deserializer : JsonDeserializer<JWK>() {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext?): JWK {
      val typeRef = object : TypeReference<HashMap<String, Any>>() {}
      val node = p.readValueAs(typeRef) as HashMap<String, Any>
      return JWK.parse(node)
    }
  }
}