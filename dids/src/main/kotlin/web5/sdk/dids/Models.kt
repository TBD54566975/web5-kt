package web5.sdk.dids

import com.fasterxml.jackson.annotation.JsonValue

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