package web5.credentials.model

public enum class ConformantConsumerDisclosure(public val str: String) {
  REQUIRED("required"),
  PREFERRED("preferred")
}

public data class ConstraintsV2(
  val fields: List<FieldV2>?,
  val limitDisclosure: ConformantConsumerDisclosure?,
)