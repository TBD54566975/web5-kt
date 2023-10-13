package web5.sdk.dids.ion.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonValue
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.nimbusds.jose.jwk.JWK

/**
 * Represents an ION document containing public keys and services. See bullet 2 in https://identity.foundation/sidetree/spec/#replace.
 *
 * @property publicKeys List of public keys.
 * @property services List of services.
 */
public data class Document(
  val publicKeys: List<PublicKey> = emptyList(),
  val services: List<Service> = emptyList()
)

/**
 * Represents an ION service. See bullet 3 in https://identity.foundation/sidetree/spec/#add-services.
 *
 * @property id The service ID.
 * @property type The service type.
 * @property serviceEndpoint The service endpoint.
 */
public data class Service(
  public val id: String,
  public val type: String,
  public val serviceEndpoint: String
)

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
  public val publicKeyJwk: JWK? = null,
  public val purposes: List<PublicKeyPurpose> = emptyList()
)

/**
 * JacksonJWK is a utility class that facilitates serialization for [JWK] types, so that it's easy to integrate with any
 * class that is meant to be serialized to/from JSON.
 */
private class JacksonJwk {
  /**
   * [Serializer] implements [JsonSerializer] for use with the [JsonSerialize] annotation from Jackson.
   */
  object Serializer : JsonSerializer<JWK>() {
    override fun serialize(value: JWK, gen: JsonGenerator, serializers: SerializerProvider) {
      with(gen) {
        writeObject(value.toJSONObject())
      }
    }
  }

  /**
   * [Deserializer] implements [JsonDeserializer] for use with the [JsonDeserialize] annotation from Jackson.
   */
  object Deserializer : JsonDeserializer<JWK>() {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext?): JWK {
      @Suppress("UNCHECKED_CAST")
      val node = p.readValueAs(Map::class.java) as MutableMap<String, Any>
      return JWK.parse(node)
    }
  }
}

/**
 * Enum representing the purpose of a public key. See bullet 3.5 of https://identity.foundation/sidetree/spec/#add-public-keys
 */
public enum class PublicKeyPurpose(@get:JsonValue public val code: String) {
  AUTHENTICATION("authentication"),
  KEY_AGREEMENT("keyAgreement"),
  ASSERTION_METHOD("assertionMethod"),
  CAPABILITY_DELEGATION("capabilityDelegation"),
  CAPABILITY_INVOCATIO("capabilityInvocation"),
}

/**
 * Sealed class representing a patch action in the ION document. See https://identity.foundation/sidetree/spec/#did-state-patches
 */
@JsonTypeInfo(
  use = JsonTypeInfo.Id.NAME,
  include = JsonTypeInfo.As.PROPERTY,
  property = "action"
)
@JsonSubTypes(
  JsonSubTypes.Type(AddServicesAction::class, name = "add-services"),
  JsonSubTypes.Type(ReplaceAction::class, name = "replace"),
  JsonSubTypes.Type(RemoveServicesAction::class, name = "remove-services"),
  JsonSubTypes.Type(AddPublicKeysAction::class, name = "add-public-keys"),
  JsonSubTypes.Type(RemovePublicKeysAction::class, name = "remove-public-keys"),
)
public sealed class PatchAction

/**
 * Represents an "add_services" patch action in the ION document as defined in https://identity.foundation/sidetree/spec/#add-services.
 *
 * @property services List of services to add.
 */
public data class AddServicesAction(
  public val services: List<Service> = emptyList()
) : PatchAction()

/**
 * Represents a "replace" patch action in the ION document as defined in https://identity.foundation/sidetree/spec/#replace.
 *
 * @property document The document to replace.
 */
public data class ReplaceAction(
  val document: Document? = null
) : PatchAction()

/** Model for https://identity.foundation/sidetree/spec/#remove-services */
public data class RemoveServicesAction(
  val ids: List<String>
) : PatchAction()

/** Model for https://identity.foundation/sidetree/spec/#add-public-keys */
public data class AddPublicKeysAction(
  val publicKeys: List<PublicKey>
) : PatchAction()

/** Model for https://identity.foundation/sidetree/spec/#remove-public-keys */
public data class RemovePublicKeysAction(
  val ids: List<String>
) : PatchAction()

/**
 * Represents a delta in the ION document as defined in bullet 3 of https://identity.foundation/sidetree/spec/#create
 *
 * @property patches List of patch actions.
 * @property updateCommitment Update commitment.
 */
public data class Delta(
  public val patches: List<PatchAction>,
  public val updateCommitment: String
)

/**
 * Represents operation suffix data object as defined in bullet 6 of https://identity.foundation/sidetree/spec/#create
 *
 * @property deltaHash Delta hash.
 * @property recoveryCommitment Recovery commitment.
 */
public data class OperationSuffixDataObject(
  public val deltaHash: String,
  public val recoveryCommitment: String
)

/**
 * Type alias for commitment.
 */
public typealias Commitment = String

/**
 * Type alias for reveal value.
 */
public typealias Reveal = String

/**
 * Sidetree API create operation as defined in https://identity.foundation/sidetree/api/#create
 */
public data class SidetreeCreateOperation(
  public val type: String,
  public val delta: Delta,
  public val suffixData: OperationSuffixDataObject) {

}

/**
 * Sidetree update operation as defined in https://identity.foundation/sidetree/api/#update
 */
public data class SidetreeUpdateOperation(
  public val type: String,
  public val didSuffix: String,
  public val revealValue: String,
  public val delta: Delta,
  public val signedData: String,
)

/**
 * Update operation signed data object as defined in https://identity.foundation/sidetree/spec/#update-signed-data-object
 */
public data class UpdateOperationSignedData(
  @JsonSerialize(using = JacksonJwk.Serializer::class)
  @JsonDeserialize(using = JacksonJwk.Deserializer::class)
  public val updateKey: JWK,
  public val deltaHash: String,
)

/**
 * InitialState is the initial state of a DID Document as defined in the spec
 * https://identity.foundation/sidetree/spec/#long-form-did-uris
 */
internal data class InitialState(
  val suffixData: OperationSuffixDataObject,
  val delta: Delta,
)

/**
 * Metadata about the did method as defined in bullet 3 (subitem 'method') of https://identity.foundation/sidetree/spec/#did-resolver-output
 */
public class MetadataMethod(
  public val published: Boolean,
  public val recoveryCommitment: String,
  public val updateCommitment: String,
)