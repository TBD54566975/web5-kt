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

