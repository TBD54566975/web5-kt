package web5.credentials.model

public class InputDescriptorV2(
  public val id: String,
  public val name: String?,
  public val purpose: String?,
  public val format: Format?,
  public val constraints: ConstraintsV2?
)