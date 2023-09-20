package web5.credentials.model

public data class PresentationDefinitionV2(
  val id: String,
  val name: String?,
  val purpose: String?,
  val format: Format?,
  val inputDescriptors: List<InputDescriptorV2>,
  val frame: Map<String, Any>?,
)