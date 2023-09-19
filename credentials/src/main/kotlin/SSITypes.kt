package web5.credentials

public typealias CredentialSubject = com.danubetech.verifiablecredentials.CredentialSubject
public typealias VerifiableCredentialType = com.danubetech.verifiablecredentials.VerifiableCredential
public typealias VerifiablePresentationType = com.danubetech.verifiablecredentials.VerifiablePresentation
public typealias CredentialStatus = com.danubetech.verifiablecredentials.credentialstatus.CredentialStatus

// Object as defined in https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition
public data class PresentationDefinitionV2(
  val id: String,
  val name: String?,
  val purpose: String?,
  val format: Format?,
  val inputDescriptors: List<InputDescriptorV2>,
  val frame: Map<String, Any>?,
)

// Object defined in the "format" bullet point in https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition
public data class Format(
  val jwt: JwtObject?,
  val jwtVc: JwtObject?,
  val jwtVp: JwtObject?,
)

public data class JwtObject(
  val alg: List<String>,
)

// Object as defined in https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object
public data class InputDescriptorV2(
  val id: String,
  val name: String?,
  val purpose: String?,
  val format: Format?,
  val constraints: ConstraintsV2?,
)

public data class ConstraintsV2(
  val fields: List<FieldV2>?,
  val limitDisclosure: ConformantConsumerDisclosure?,
)

public enum class ConformantConsumerDisclosure(public val str: String) {
  REQUIRED("required"),
  PREFERRED("preferred"),
}

public data class FieldV2(
  val id: String?,
  val path: List<String>?,
  val purpose: String?,
  val name: String?,
)