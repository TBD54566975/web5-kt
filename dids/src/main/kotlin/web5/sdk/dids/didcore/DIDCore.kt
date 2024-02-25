package web5.sdk.dids.didcore

import com.fasterxml.jackson.annotation.JsonValue


public interface VMSelector
public class ID(public val value: String) : VMSelector

public enum class Purpose : VMSelector {
  AssertionMethod,
  Authentication,
  CapabilityDelegation,
  CapabilityInvocation,
  KeyAgreement
}

/**
 * Enum representing the purpose of a public key.
 */
public enum class PublicKeyPurpose(@get:JsonValue public val code: String) {
  AUTHENTICATION("authentication"),
  KEY_AGREEMENT("keyAgreement"),
  ASSERTION_METHOD("assertionMethod"),
  CAPABILITY_DELEGATION("capabilityDelegation"),
  CAPABILITY_INVOCATION("capabilityInvocation"),
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
