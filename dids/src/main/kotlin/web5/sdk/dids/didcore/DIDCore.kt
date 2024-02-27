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
public enum class Purpose(public val value: String) : VMSelector {
  AssertionMethod("assertionMethod"),
  Authentication("authentication"),
  CapabilityDelegation("capabilityDelegation"),
  CapabilityInvocation("capabilityInvocation"),
  KeyAgreement("keyAgreement");

  public companion object {
    private val map = entries.associateBy(Purpose::value)

    /**
     * Retrieve Purpose enum from String value.
     *
     * @param value of the purpose
     * @return Purpose enum
     */
    public fun fromValue(value: String): Purpose? = map[value]
  }
}

