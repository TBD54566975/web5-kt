package web5.security

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.util.Base64URL

/**
 * Represents a disclosure for an Object Property as defined in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-disclosures-for-object-prop.
 */
public class ObjectDisclosure(
  public val salt: String,
  public val claimName: String,
  public val claimValue: Any,
  raw: String? = null,
  mapper: ObjectMapper? = null) : Disclosure() {

  override val raw: String = raw ?: serialize(mapper!!)


  override fun serialize(mapper: ObjectMapper): String {
    val value = mapper.writeValueAsString(claimValue)
    val jsonEncoded = """["$salt", "$claimName", $value]"""

    return Base64URL.encode(jsonEncoded).toString()
  }
}

/**
 * Generalization of Disclosures.
 */
public sealed class Disclosure {
  public abstract val raw: String

  /**
   * Returns the base64url encoding of the bytes in the JSON encoded array that represents this disclosure. [mapper] is
   * used to do the JSON encoding.
   */
  public abstract fun serialize(mapper: ObjectMapper): String

  /**
   * Returns the result of hashing this disclosure as described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-hashing-disclosures.
   */
  public fun digest(hashAlg: HashFunc): String {
    return Base64URL.encode(hashAlg(raw.toByteArray())).toString()
  }

  public companion object {
    /**
     * Returns a [Disclosure] given the base64url encoding of the json encoded byte representation. This operation
     * is the reverse of [serialize].
     *
     * @throws DisclosureClaimNameNotStringException if the second element of the 3-element disclosure is not a string.
     * @throws DisclosureSizeNotValidException if the disclosure does not have exactly 2 or 3 elements.
     */
    @Throws(
      DisclosureClaimNameNotStringException::class,
      DisclosureSizeNotValidException::class,
    )
    @JvmStatic
    public fun parse(encodedDisclosure: String): Disclosure {
      // Decode the base64-encoded disclosure
      val disclosureJson = Base64URL(encodedDisclosure).decodeToString()

      // Parse the disclosure JSON into a list of elements
      val disclosureElems = defaultMapper.readValue(disclosureJson, List::class.java)

      // Ensure that the disclosure is object or array disclosure
      when (disclosureElems.size) {
        2 -> {
          // Create a Disclosure instance
          return ArrayDisclosure(
            salt = disclosureElems[0] as String,
            claimValue = disclosureElems[1] as Any,
            raw = encodedDisclosure
          )
        }

        3 -> {
          // Extract the elements
          val disclosureClaimName = disclosureElems[1] as? String
            ?: throw DisclosureClaimNameNotStringException("Second element of disclosure must be a string")

          // Create a Disclosure instance
          return ObjectDisclosure(
            salt = disclosureElems[0] as String,
            claimName = disclosureClaimName,
            claimValue = disclosureElems[2] as Any,
            raw = encodedDisclosure
          )
        }

        else -> throw DisclosureSizeNotValidException(
          "Disclosure \"$encodedDisclosure\" must have exactly 2 or 3 elements"
        )
      }
    }
  }
}

/**
 * Represents the disclosure of an Array Element as described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-disclosures-for-array-eleme.
 */
public class ArrayDisclosure(
  public val salt: String,
  public val claimValue: Any,
  raw: String? = null,
  mapper: ObjectMapper? = null
) : Disclosure() {
  override val raw: String = raw ?: serialize(mapper!!)

  override fun serialize(mapper: ObjectMapper): String {
    val value = mapper.writeValueAsString(claimValue)
    val jsonEncoded = """["$salt", $value]"""

    return Base64URL.encode(jsonEncoded).toString()
  }
}