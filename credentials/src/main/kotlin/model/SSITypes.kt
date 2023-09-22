package web5.credentials.model

/** Verifiable Credentials
 *
 * A verifiable credential is a tamper-evident credential that has authorship that can be cryptographically verified.
 *
 * @see [VC Data Model](https://www.w3.org/TR/vc-data-model/)
 */

public typealias VerifiableCredentialType = com.danubetech.verifiablecredentials.VerifiableCredential
public typealias CredentialStatus = com.danubetech.verifiablecredentials.credentialstatus.CredentialStatus
public typealias CredentialSubject = com.danubetech.verifiablecredentials.CredentialSubject
public typealias VerifiablePresentationType = com.danubetech.verifiablecredentials.VerifiablePresentation


/** Presentation Exchange
 *
 * Presentation Exchange specification codifies a Presentation Definition data format Verifiers can use to articulate
 * proof requirements, and a Presentation Submission data format Holders can use to describe proofs submitted in
 * accordance with them.
 *
 * * @see [Presentation Exchange](https://identity.foundation/presentation-exchange/)
 * */

public class PresentationDefinitionV2(
  public val id: String,
  public val name: String?,
  public val purpose: String?,
  public val format: Format?,
  public val submissionRequirement: SubmissionRequirement?,
  public val inputDescriptors: List<InputDescriptorV2>,
  public val frame: Map<String, Any>?,
)

public class InputDescriptorV2(
  public val id: String,
  public val name: String?,
  public val purpose: String?,
  public val format: Format?,
  public val constraints: ConstraintsV2?
)

public class ConstraintsV2(
  public val fields: List<FieldV2>?,
  public val limitDisclosure: ConformantConsumerDisclosure?,
)

public class FieldV2(
  public val id: String?,
  public val path: List<String>?,
  public val purpose: String?,
  public val name: String?
)

public enum class ConformantConsumerDisclosure(public val str: String) {
  REQUIRED("required"),
  PREFERRED("preferred")
}

public class Format(
  public val jwt: JwtObject?,
  public val jwtVc: JwtObject?,
  public val jwtVp: JwtObject?
)

public class JwtObject(
  public val alg: List<String>,
)

public class SubmissionRequirement(
  public val name: String?,
  public val purpose: String?,
  public val rule: Rules,
  public val count: Int?,
  public val min: Int?,
  public val max: Int?,
  public val from: String?,
  public val fromNested: List<SubmissionRequirement>?
)

public enum class Rules {
  All, Pick
}

