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
 * @see [Presentation Exchange](https://identity.foundation/presentation-exchange/)
 */

public class PresentationDefinitionV2(
  public val id: String,
  public val name: String? = null,
  public val purpose: String? = null,
  public val format: Format? = null,
  public val submissionRequirements: List<SubmissionRequirement>? = null,
  public val inputDescriptors: List<InputDescriptorV2>,
  public val frame: Map<String, Any>? = null
)

public class InputDescriptorV2(
  public val id: String,
  public val name: String? = null,
  public val purpose: String? = null,
  public val format: Format? = null,
  public val constraints: ConstraintsV2
)

public class ConstraintsV2(
  public val fields: List<FieldV2>? = null,
  public val limitDisclosure: ConformantConsumerDisclosure? = null
)

public class FieldV2(
  public val id: String? = null,
  public val path: List<String>,
  public val purpose: String? = null,
  public val filter: FilterV2? = null,
  public val predicate: Optionality? = null,
  public val name: String? = null,
  public val optional: Boolean? = null
)

public enum class ConformantConsumerDisclosure(public val str: String) {
  REQUIRED("required"),
  PREFERRED("preferred")
}

public class Format(
  public val jwt: JwtObject? = null,
  public val jwtVc: JwtObject? = null,
  public val jwtVp: JwtObject? = null
)

public class JwtObject(
  public val alg: List<String>
)

public class SubmissionRequirement(
  public val name: String? = null,
  public val purpose: String? = null,
  public val rule: Rules,
  public val count: Int? = null,
  public val min: Int? = null,
  public val max: Int? = null,
  public val from: String? = null,
  public val fromNested: List<SubmissionRequirement>? = null
)

public enum class Rules {
  All, Pick
}

public sealed class NumberOrString {
  public class NumberValue(public val value: Double) : NumberOrString()
  public class StringValue(public val value: String) : NumberOrString()
}


public enum class Optionality {
  Required,
  Preferred
}

public class FilterV2(
  public val const: NumberOrString? = null,
  public val enum: List<NumberOrString>? = null,
  public val exclusiveMinimum: NumberOrString? = null,
  public val exclusiveMaximum: NumberOrString? = null,
  public val format: String? = null,
  public val formatMaximum: String? = null,
  public val formatMinimum: String? = null,
  public val formatExclusiveMaximum: String? = null,
  public val formatExclusiveMinimum: String? = null,
  public val minLength: Int? = null,
  public val maxLength: Int? = null,
  public val minimum: NumberOrString? = null,
  public val maximum: NumberOrString? = null,
  public val not: Any? = null,
  public val pattern: String? = null,
  public val type: String
)
