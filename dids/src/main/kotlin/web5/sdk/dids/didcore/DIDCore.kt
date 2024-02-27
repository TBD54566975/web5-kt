package web5.sdk.dids.didcore

import com.fasterxml.jackson.annotation.JsonValue

/**
 * VerificationMethod Selector.
 */
public interface VMSelector

/**
 * ID.
 * @property value The value of the ID
 */
public class ID(public val value: String) : VMSelector


/**
 * Enum representing the purpose of a public key.
 */
public enum class Purpose : VMSelector {
  AssertionMethod,
  Authentication,
  CapabilityDelegation,
  CapabilityInvocation,
  KeyAgreement
}

