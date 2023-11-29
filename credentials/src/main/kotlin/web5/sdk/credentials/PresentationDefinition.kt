package web5.sdk.credentials

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonRawValue
import com.fasterxml.jackson.databind.JsonNode
import com.networknt.schema.JsonSchema
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion

/**
 * Presentation Exchange
 *
 * Presentation Exchange specification codifies a Presentation Definition data format Verifiers can use to articulate
 * proof requirements, and a Presentation Submission data format Holders can use to describe proofs submitted in
 * accordance with them.
 *
 * @see [Presentation Definition](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition)
 */

public class PresentationDefinitionV2(
  public val id: String,
  public val name: String? = null,
  public val purpose: String? = null,
  public val format: Format? = null,
  @JsonProperty("submission_requirements")
  public val submissionRequirements: List<SubmissionRequirement>? = null,
  @JsonProperty("input_descriptors")
  public val inputDescriptors: List<InputDescriptorV2>,
  public val frame: Map<String, Any>? = null
)

/**
 * Represents an input descriptor in a presentation definition.
 *
 * @see [Input Descriptor](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
 */
public class InputDescriptorV2(
  public val id: String,
  public val name: String? = null,
  public val purpose: String? = null,
  public val format: Format? = null,
  public val constraints: ConstraintsV2
)

/**
 * Represents constraints for an input descriptor.
 *
 * @See 'contraints object' defined in [Input Descriptor](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
 */
public class ConstraintsV2(
  public val fields: List<FieldV2>? = null,
  @JsonProperty("limit_disclosure")
  public val limitDisclosure: ConformantConsumerDisclosure? = null
)

/**
 * Represents a field in a presentation input descriptor.
 *
 * @See 'fields object' as defined in [Input Descriptor](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
 */
public class FieldV2(
  public val id: String? = null,
  public val path: List<String>,
  public val purpose: String? = null,
  @JsonRawValue
  @JsonProperty("filter")
  private val filterJson: JsonNode? = null,
  public val predicate: Optionality? = null,
  public val name: String? = null,
  public val optional: Boolean? = null
) {
  @get:JsonIgnore
  public val filterSchema: JsonSchema?
    get() {
      if (filterJson == null) return null
      val schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7)
      return schemaFactory.getSchema(filterJson)
    }
}

/**
 * Enumeration representing consumer disclosure options. Represents the possible values of `limit_disclosure' property
 * as defined in [Input Descriptor](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object)
 */
public enum class ConformantConsumerDisclosure(public val str: String) {
  REQUIRED("required"),
  PREFERRED("preferred")
}


/**
 * Represents the format of a presentation definition.
 *
 * @See 'format' as defined in [Input Descriptor](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object) and [Registry](https://identity.foundation/claim-format-registry/#registry)
 */
public class Format(
  public val jwt: JwtObject? = null,
  @JsonProperty("jwt_vc")
  public val jwtVc: JwtObject? = null,
  @JsonProperty("jwt_vp")
  public val jwtVp: JwtObject? = null
)

/**
 * Represents a JWT object.
 */
public class JwtObject(
  public val alg: List<String>
)

/**
 * Represents submission requirements for a presentation definition.
 */
public class SubmissionRequirement(
  public val name: String? = null,
  public val purpose: String? = null,
  public val rule: Rules,
  public val count: Int? = null,
  public val min: Int? = null,
  public val max: Int? = null,
  public val from: String? = null,
  @JsonProperty("from_nested")
  public val fromNested: List<SubmissionRequirement>? = null
)

/**
 * Enumeration representing presentation rule options.
 */
// TODO this does not serialize correctly but sub reqs not supported right now
public enum class Rules {
  All, Pick
}

/**
 * Enumeration representing optionality.
 */
public enum class Optionality {
  Required,
  Preferred
}

