package web5.sdk.dids.didcore


public interface VMSelector
public class ID(public val value: String) : VMSelector

public enum class Purpose : VMSelector {
  AssertionMethod,
  Authentication,
  CapabilityDelegation,
  CapabilityInvocation,
  KeyAgreement
}


public class DocumentMetadata(
  public val created: String,
  public val updated: String,
  public val deactivated: Boolean,
  public val versionId: String,
  public val nextUpdate: String,
  public val nextVersionId: String,
  public val equivalentId: String,
  public val canonicalId: String
)
