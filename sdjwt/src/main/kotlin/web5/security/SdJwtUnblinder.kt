package web5.security

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import java.util.Stack

/**
 * Options for verification of an [SdJwt].
 *
 * [holderBindingOption] is used to tell whether holder binding should be checked. When [HolderBindingOption.VerifyHolderBinding]
 * is selected, then [desiredNonce], [desiredAudience], and [holderVerifierPublicJwk] are required.
 *
 * Callers MUST set the [supportedAlgorithms] to declare which set of algorithms they explicitly support. This follows
 * the guidance from https://www.rfc-editor.org/rfc/rfc8725.html#name-use-appropriate-algorithms
 */
public class VerificationOptions(
  public val issuerPublicJwk: JWK,

  public val supportedAlgorithms: Set<JWSAlgorithm>,

  public val holderBindingOption: HolderBindingOption,

  // The nonce and audience to check for when doing holder binding verification.
  // Needed only when holderBindingOption == VerifyHolderBinding.
  public val desiredNonce: String? = null,
  public val desiredAudience: String? = null,
  public val holderVerifierPublicJwk: JWK? = null,
)

/** Options for holder binding processing. */
public enum class HolderBindingOption(public val value: Boolean) {
  VerifyHolderBinding(true),
  SkipVerifyHolderBinding(false)
}

internal fun JWTClaimsSet.getHashAlg(): HashFunc {
  val hashName = when (val hashNameValue = this.getClaim(sdAlgClaimName)) {
    null -> {
      Hash.SHA_256.ianaName
    }

    is String -> {
      hashNameValue
    }

    else -> {
      throw IllegalArgumentException("Converting _sd_alg claim value to string")
    }
  }

  return when (hashName) {
    Hash.SHA_256.ianaName -> Hash.SHA_256.hashFunc
    Hash.SHA_512.ianaName -> Hash.SHA_512.hashFunc
    else -> throw IllegalArgumentException("Unsupported hash name $hashName")
  }
}

/** Responsible for taking an SD-JWT in serialization format and unblinding it. */
public class SdJwtUnblinder {
  /**
   * Unblinds [serializedSdJwt]. Follows the algorithm specified in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.1
   *
   * An unblinded [JWTClaimsSet], where the hidden values in the `issuerJwt` are replaced with values from the
   * `disclosures` presented.
   */
  @Throws(Exception::class)
  public fun unblind(
    serializedSdJwt: String
  ): JWTClaimsSet {
    // 2. Separate the Presentation into the SD-JWT, the Disclosures (if any), and the Holder Binding JWT (if provided).
    val sdJwt = SdJwt.parse(serializedSdJwt)

    // Check that the _sd_alg claim value is understood and the hash algorithm is deemed secure.
    val hashAlg = sdJwt.issuerJwt.jwtClaimsSet.getHashAlg()

    // For each Disclosure provided, calculate the digest over the base64url-encoded string as described in Section 5.1.1.2.
    val disclosuresByDigest = sdJwt.disclosures.associateBy { it.digest(hashAlg) }

    // Process the Disclosures and _sd keys in the SD-JWT as follows:
    //
    // Create a copy of the SD-JWT payload, if required for further processing.
    val tokenClaims = sdJwt.issuerJwt.jwtClaimsSet.toJSONObject().toMutableMap()
    processPayload(tokenClaims, disclosuresByDigest)

    return JWTClaimsSet.parse(tokenClaims)
  }


  /**
   * ProcessPayload will recursively remove all _sd fields from the claims object, and replace it with the information found
   * inside disclosuresByDigest.
   */
  @Throws(Exception::class)
  private fun processPayload(
    claims: MutableMap<String, Any>,
    disclosuresByDigest: Map<String, Disclosure>
  ) {
    val workLeft = createWorkFrom(claims, null)
    unblind(workLeft, disclosuresByDigest, claims)

    claims.remove(sdAlgClaimName)
  }

  private class Work(
    val insertionPoint: Any,
    val disclosureDigest: String,
  )

  private fun createWorkFrom(claims: Any, parent: Any?): Stack<Work> {
    val result: Stack<Work> = Stack()
    when (claims) {
      is Map<*, *> -> {
        val sdClaimValue = claims[sdClaimName]
        if (sdClaimValue != null) {
          // If the key does not refer to an array, the Verifier MUST reject the Presentation.
          require(sdClaimValue is List<*>) {
            "\"_sd\" key MUST refer to an array"
          }
          for (digest in sdClaimValue) {
            require(digest is String) {
              "all values in \"_sd\" MUST be strings"
            }
            result.add(Work(claims, digest))
          }
          @Suppress("UNCHECKED_CAST")
          (claims as MutableMap<String, Any>).remove(sdClaimName)
        }

        val arrayElementDigest = claims[blindedArrayKey]
        if (arrayElementDigest != null) {
          require(arrayElementDigest is String) {
            "Value of \"...\" MUST be a string"
          }
          require(parent != null && parent is List<*>) {
            "Parent must be an array"

          }
          result.add(Work(parent, arrayElementDigest))
        }
        for (value in claims.values) {
          result.addAll(createWorkFrom(value as Any, claims))
        }
      }

      is List<*> -> {
        for (claim in claims.reversed()) {
          result.addAll(createWorkFrom(claim!!, claims))
        }
        @Suppress("UNCHECKED_CAST")
        (claims as MutableList<Any>).removeAll { true }
      }
    }

    return result
  }

  private fun unblind(
    workLeft: Stack<Work>,
    disclosuresByDigest: Map<String, Disclosure>,
    claims: MutableMap<String, Any>) {
    val digestsFound = HashSet<String>()
    while (workLeft.isNotEmpty()) {
      val work = workLeft.pop()
      val digestValue = work.disclosureDigest
      val insertionPoint = work.insertionPoint

      // Compare the value with the digests calculated previously and find the matching Disclosure. If no such Disclosure can be
      // found, the digest MUST be ignored.
      val disclosure = disclosuresByDigest[digestValue] ?: continue

      // If any digests were found more than once, the Verifier MUST reject the Presentation.
      require(!digestsFound.contains(digestValue)) {
        "Digest \"$digestValue\" found more than once"
      }
      digestsFound.add(digestValue)

      when (disclosure) {
        is ObjectDisclosure -> {
          require(insertionPoint is MutableMap<*, *>) {
            "Insertion point for object disclosure must be a map"
          }

          if (insertionPoint.containsKey(disclosure.claimName) || claims.containsKey(disclosure.claimName)) {
            throw Exception("Claim name \"${disclosure.claimName}\" already exists")
          }
          fun insert(m: MutableMap<String, Any>) {
            m.put(disclosure.claimName, disclosure.claimValue)
          }
          @Suppress("UNCHECKED_CAST")
          insert(insertionPoint as MutableMap<String, Any>)

          // If the decoded value contains an _sd key in an object, recursively process the key using the steps described in (*).
          if (disclosure.claimValue is Map<*, *>) {
            workLeft.addAll(createWorkFrom(disclosure.claimValue, insertionPoint))
          }
        }

        is ArrayDisclosure -> {
          require(insertionPoint is MutableList<*>) {
            "Insertion point for array disclosure must be an array"
          }

          // find and then replace insertion point
          @Suppress("UNCHECKED_CAST")
          (insertionPoint as MutableList<Any>).add(disclosure.claimValue)

          // If the decoded value contains an _sd key in an object, recursively process the key using the steps described in (*).
          if (disclosure.claimValue is Map<*, *>) {
            workLeft.addAll(createWorkFrom(disclosure.claimValue, insertionPoint))
          }
        }
      }
    }
  }
}