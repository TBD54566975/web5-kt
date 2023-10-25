package web5.security

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSObject.State
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT

private const val separator = "~"

/**
 * Represents a Selective Disclosure JWT as defined in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-terms-and-definitions.
 * A more detailed overview is available in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-sd-jwt-structure.
 */
public class SdJwt(
  public val issuerJwt: SignedJWT,
  public val disclosures: Iterable<Disclosure>,
  public val keyBindingJwt: SignedJWT? = null) {
  init {
    require(issuerJwt.state == State.SIGNED) {
      "given issuerJwt \"${issuerJwt.serialize()}\" MUST be signed"
    }
    if (keyBindingJwt != null) {
      require(keyBindingJwt.state == State.SIGNED) {
        "given keyBindingJwt \"${keyBindingJwt.serialize()}\" MUST be signed"
      }
    }
  }

  /**
   * Serializes this sd-jwt to the serialization format described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-sd-jwt-structure
   */
  public fun serialize(mapper: ObjectMapper): String {
    return buildList {
      add(issuerJwt.serialize())
      addAll(disclosures.map { it.serialize(mapper) })
      add(keyBindingJwt?.serialize() ?: "")
    }.joinToString(separator)
  }

  public companion object {
    /**
     * The reverse of the [serialize] operation. Given the serialized format of an SD-JWT, returns a [SdJwt].
     * Verification of the signature of each JWT is left to the caller.
     */
    @JvmStatic
    public fun parse(input: String): SdJwt {
      val parts = input.split(separator)
      require(parts.isNotEmpty()) {
        "input must not be empty"
      }
      val keyBindingInput = parts[parts.size - 1]
      val keyBindingJwt = keyBindingInput.takeUnless { it.isEmpty() }?.run(SignedJWT::parse)
      return SdJwt(
        SignedJWT.parse(parts[0]),
        parts.subList(1, parts.size - 1).map { Disclosure.parse(it) },
        keyBindingJwt,
      )
    }
  }
}

/**
 * The hash algorithm as described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-hash-function-claim
 */
public typealias HashFunc = (ByteArray) -> ByteArray

internal val defaultMapper = jacksonObjectMapper()

/**
 * Represents a disclosure for an Object Property as defined in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-disclosures-for-object-prop.
 */
public class ObjectDisclosure(
  public val salt: String,
  public val claimName: String,
  public val claimValue: Any) : Disclosure {


  override fun serialize(mapper: ObjectMapper): String {
    val value = mapper.writeValueAsString(claimValue)
    val jsonEncoded = """["$salt", "$claimName", $value]"""

    return Base64URL.encode(jsonEncoded).toString()
  }
}

/**
 * Generalization of Disclosures.
 */
public interface Disclosure {

  /**
   * Returns the base64url encoding of the bytes in the JSON encoded array that represents this disclosure. [mapper] is
   * used to do the JSON encoding.
   */
  public fun serialize(mapper: ObjectMapper = defaultMapper): String

  /**
   * Returns the result of hashing this disclosure as described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-hashing-disclosures.
   */
  public fun digest(hashAlg: HashFunc, mapper: ObjectMapper = defaultMapper): String {
    val e = serialize(mapper)
    return Base64URL.encode(hashAlg(e.toByteArray())).toString()
  }

  public companion object {
    /**
     * Returns a [Disclosure] given the base64url encoding of the json encoded byte representation. This operation
     * is the reverse of [serialize].
     */
    @JvmStatic
    public fun parse(encodedDisclosure: String): Disclosure {
      // Decode the base64-encoded disclosure
      val disclosureJson = Base64URL(encodedDisclosure).decodeToString()

      // Parse the disclosure JSON into a list of elements
      val disclosureElems = defaultMapper.readValue(disclosureJson, List::class.java)

      // Ensure that the disclosure is object or array disclosure
      when (disclosureElems.size) {
        3 -> {
          // Extract the elements
          val disclosureClaimName = disclosureElems[1] as? String
            ?: throw IllegalArgumentException("Second element of disclosure must be a string")

          // Create a Disclosure instance
          return ObjectDisclosure(
            salt = disclosureElems[0] as String,
            claimName = disclosureClaimName,
            claimValue = disclosureElems[2] as Any
          )
        }

        2 -> {
          // Create a Disclosure instance
          return ArrayDisclosure(
            salt = disclosureElems[0] as String,
            claimValue = disclosureElems[1] as Any
          )
        }

        else -> throw IllegalArgumentException("Disclosure \"$encodedDisclosure\" must have exactly 3 elements")
      }
    }
  }
}

/**
 * Represents the disclosure of an Array Element as described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-disclosures-for-array-eleme.
 */
public class ArrayDisclosure(
  public val salt: String,
  public val claimValue: Any) : Disclosure {

  override fun serialize(mapper: ObjectMapper): String {
    val value = mapper.writeValueAsString(claimValue)
    val jsonEncoded = """["$salt", $value]"""

    return Base64URL.encode(jsonEncoded).toString()
  }
}

