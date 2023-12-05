package web5.sdk.credentials.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

/**
 * Represents a presentation submission object.
 *
 * @see [Presentation Submission](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission)
 */
public class PresentationSubmission(
  val id: String,
  @JsonProperty("definition_id")
  val definitionId: String,
  @JsonProperty("descriptor_map")
  val descriptorMap: List<DescriptorMap>
)

/**
 * Represents descriptor map for a presentation submission.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DescriptorMap(
  val id: String,
  val format: String,
  val path: String,
  @JsonProperty("path_nested")
  val pathNested: DescriptorMap? = null
)