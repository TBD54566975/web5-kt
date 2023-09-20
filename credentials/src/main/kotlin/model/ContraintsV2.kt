package web5.credentials.model

public enum class ConformantConsumerDisclosure(public val str: String) {
  REQUIRED("required"),
  PREFERRED("preferred")
}

public class ConstraintsV2(
  public val fields: List<FieldV2>?,
  public val limitDisclosure: ConformantConsumerDisclosure?,
)