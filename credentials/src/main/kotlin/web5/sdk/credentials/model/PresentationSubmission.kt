package web5.sdk.credentials.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

/**
 * Represents a presentation submission object.
 *
 * @see [Presentation Submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
 */
public class PresentationSubmission(
  public val id: String,
  @JsonProperty("definition_id")
  public val definitionId: String,
  @JsonProperty("descriptor_map")
  public val descriptorMap: List<InputDescriptorMapping>
)

/**
 * Represents descriptor map for a presentation submission.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InputDescriptorMapping(
  public val id: String,
  public val format: String,
  public val path: String,
  @JsonProperty("path_nested")
  public val pathNested: InputDescriptorMapping? = null
)