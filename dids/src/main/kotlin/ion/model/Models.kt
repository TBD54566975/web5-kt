package web5.dids.ion.model

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonClassDiscriminator

/**
 * Represents an ION document containing public keys and services.
 *
 * @property publicKeys List of public keys.
 * @property services List of services.
 */
@Serializable
public data class Document(
  val publicKeys: List<PublicKey> = emptyList(),
  val services: List<Service> = emptyList()
)

/**
 * Represents an ION service.
 *
 * @property id The service ID.
 * @property type The service type.
 * @property serviceEndpoint The service endpoint.
 */
@Serializable
public data class Service(
  public val id: String,
  public val type: String,
  public val serviceEndpoint: String
)

/**
 * Represents a public key in the ION document as defined in item 3 of https://identity.foundation/sidetree/spec/#add-public-keys
 */
@Serializable
public data class PublicKey(
  public val id: String,
  public val type: String,
  public val controller: String? = null,
  public val publicKeyJwk: JsonWebKey? = null,
  public val purposes: List<PublicKeyPurpose> = emptyList()
)

/**
 * Represents a JSON Web Key (JWK) for public keys.
 *
 * @property kty Key Type.
 * @property use Key Use.
 * @property keyOps List of Key Operations.
 * @property alg Algorithm.
 * @property kid Key ID.
 * @property x5u X.509 URL.
 * @property x5c List of X.509 Certificate Chain.
 * @property x5t X.509 Certificate SHA-1 Thumbprint.
 * @property x5tS256 X.509 Certificate SHA-256 Thumbprint.
 * @property x5uHeaderParam Custom X.509 URL Header Parameter.
 * @property x5cHeaderParam List of Custom X.509 Certificate Chain Header Parameters.
 * @property crv Curve.
 * @property x X Coordinate.
 * @property y Y Coordinate.
 * @property d D.
 */
@Serializable
public data class JsonWebKey(
  public val kty: String? = null,
  public val use: String? = null,
  public val keyOps: List<String>? = null,
  public val alg: String? = null,
  public val kid: String? = null,
  public val x5u: String? = null,
  public val x5c: List<String>? = null,
  public val x5t: String? = null,
  public val x5tS256: String? = null,
  public val x5uHeaderParam: String? = null,
  public val x5cHeaderParam: List<String>? = null,
  public val crv: String? = null,
  public val x: String? = null,
  public val y: String? = null,
  public val d: String? = null
)

/**
 * Converts a [JWK] (from the nimbus library) to a JSON Web Key ([JsonWebKey]) object, which can be serialized in
 * kotlin.
 */
public fun JWK.toJsonWebKey(): JsonWebKey {
  return Json.decodeFromString<JsonWebKey>(toJSONString())
}

/**
 * Converts a [JsonWebKey] object to a [JWK] (from the nimbus library).
 *
 * @return JWK representation.
 */
public fun JsonWebKey.toJWK(): JWK {
  return JWK.parse(Json.encodeToString(this))
}

/**
 * Enum representing the purpose of a public key.
 */
public enum class PublicKeyPurpose {
  @SerialName("authentication")
  AUTHENTICATION,

  @SerialName("keyAgreement")
  KEY_AGREEMENT,

  @SerialName("assertionMethod")
  ASSERTION_METHOD,

  @SerialName("capabilityDelegation")
  CAPABILITY_DELEGATION,

  @SerialName("capabilityInvocation")
  CAPABILITY_INVOCATION
}

/**
 * Sealed class representing a patch action in the ION document.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("action")
public sealed class PatchAction

/**
 * Represents an "add_services" patch action in the ION document.
 *
 * @property services List of services to add.
 */
public data class AddServicesAction(
  public val services: List<Service> = emptyList()
) : PatchAction()

/**
 * Represents a "replace" patch action in the ION document.
 *
 * @property document The document to replace.
 */
@Serializable
@SerialName("replace")
public data class ReplaceAction(
  val document: Document? = null
) : PatchAction()

/**
 * Represents a delta in the ION document.
 *
 * @property patches List of patch actions.
 * @property updateCommitment Update commitment.
 */
@Serializable
public data class Delta(
  public val patches: List<PatchAction>,
  public val updateCommitment: String
)

/**
 * Represents operation suffix data object.
 *
 * @property deltaHash Delta hash.
 * @property recoveryCommitment Recovery commitment.
 */
@Serializable
public data class OperationSuffixDataObject(
  public val deltaHash: String,
  public val recoveryCommitment: String
)

/**
 * Type alias for commitment.
 */
public typealias Commitment = String

/**
 * Sidetree create operation.
 */
@Serializable
public data class SidetreeCreateOperation(
  public val type: String,
  public val delta: Delta,
  public val suffixData: OperationSuffixDataObject) {

}

/**
 * InitialState is the initial state of a DID Document as defined in the spec
 * https://identity.foundation/sidetree/spec/#long-form-did-uris
 */
@Serializable
internal data class InitialState(
  val suffixData: OperationSuffixDataObject,
  val delta: Delta,
)
