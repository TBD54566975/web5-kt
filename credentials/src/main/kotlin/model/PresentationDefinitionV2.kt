package web5.credentials.model

public class PresentationDefinitionV2(
  public val id: String,
  public val name: String?,
  public val purpose: String?,
  public val format: Format?,
  public val inputDescriptors: List<InputDescriptorV2>,
  public val frame: Map<String, Any>?,
)