package web5.credentials.model

public data class InputDescriptorV2(
  val id: String,
  val name: String?,
  val purpose: String?,
  val format: Format?,
  val constraints: ConstraintsV2?
)