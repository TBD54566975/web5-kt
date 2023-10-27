package web5.security

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject.State
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import java.security.Key
import java.security.Provider
import java.security.SignatureException

private const val separator = "~"

/**
 * Represents a Selective Disclosure JWT as defined in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-terms-and-definitions.
 * A more detailed overview is available in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-sd-jwt-structure.
 *
 * Note: While [issuerJwt] and [keyBindingJwt] are of type [SignedJWT], they may or may not be signed.
 */
public class SdJwt(
  public val issuerJwt: SignedJWT,
  public val disclosures: Iterable<Disclosure>,
  public val keyBindingJwt: SignedJWT? = null,
  private val serializedSdJwt: String? = null) {
  /** Builder class for constructing a [SdJwt]. */
  public class Builder(public var issuerHeader: JWSHeader? = null,
                       public var jwtClaimsSet: JWTClaimsSet? = null,
                       public var disclosures: Iterable<Disclosure>? = null,
                       public var keyBindingJwt: SignedJWT? = null) {

    /** Returns an [SdJwt], throwing errors when there are missing values which are required. */
    public fun build(): SdJwt {

      return SdJwt(
        SignedJWT(issuerHeader, jwtClaimsSet),
        disclosures!!,
        keyBindingJwt,
      )
    }
  }

  /**
   * Serializes this sd-jwt to the serialization format described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-sd-jwt-structure
   *
   * [issuerJwt] must have been previously signed.
   * [keyBindingJwt], if present, must have been previously signed.
   */
  public fun serialize(mapper: ObjectMapper = defaultMapper): String {
    if (serializedSdJwt != null) {
      return serializedSdJwt
    }
    require(issuerJwt.state == State.SIGNED) {
      "issuerJwt is not signed"
    }
    if (keyBindingJwt != null) {
      require(keyBindingJwt.state == State.SIGNED) {
        "keyBindingJwt is not signed"
      }
    }
    return buildList {
      add(issuerJwt.serialize())
      addAll(disclosures.map { it.serialize(mapper) })
      add(keyBindingJwt?.serialize() ?: "")
    }.joinToString(separator)
  }

  /** Signs the [issuerJwt] with [signer]. */
  @Synchronized
  public fun signAsIssuer(signer: JWSSigner) {
    issuerJwt.sign(signer)
  }

  /**
   * Signs the [keyBindingJwt] with [signer].
   */
  @Synchronized
  public fun signKeyBinding(signer: JWSSigner) {
    keyBindingJwt?.sign(signer)
  }

  /**
   * TODO: only accept a subset of algos for verification.
   * Verifies this SD-JWT according to [verificationOptions].
   */
  @Throws(Exception::class)
  public fun verify(
    verificationOptions: VerificationOptions
  ) {
    // Validate the SD-JWT:
    //
    // Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [RFC8725], Sections 3.1
    // and 3.2 for details. The none algorithm MUST NOT be accepted.
    // Validate the signature over the SD-JWT.
    // Validate the Issuer of the SD-JWT and that the signing key belongs to this Issuer.
    val verifier =
      DefaultJWSVerifierFactory().createJWSVerifier(
        issuerJwt.header,
        verificationOptions.issuerPublicJwk.toECKey().toPublicKey()
      )
    verifier.jcaContext.provider = BouncyCastleProviderSingleton.getInstance() as Provider
    if (!issuerJwt.verify(verifier)) {
      throw SignatureException("Verifying the issuerJwt failed: ${issuerJwt.serialize()}")
    }

    // Check that the SD-JWT is valid using nbf, iat, and exp claims, if provided in the SD-JWT, and not selectively disclosed.
    val claimsVerifier = DefaultJWTClaimsVerifier<SecurityContext>(null, null)
    claimsVerifier.verify(issuerJwt.jwtClaimsSet, null)

    if (verificationOptions.holderBindingOption == HolderBindingOption.VerifyHolderBinding) {
      // If Holder Binding JWT is not provided, the Verifier MUST reject the Presentation.
      require(keyBindingJwt != null) {
        "Holder binding required, but holder binding JWT not found"
      }

      // Ensure that a signing algorithm was used that was deemed secure for the application. Refer to [RFC8725], Sections 3.1
      // and 3.2 for details. The none algorithm MUST NOT be accepted.

      // Validate the signature over the Holder Binding JWT.
      // Check that the Holder Binding JWT is valid using nbf, iat, and exp claims, if provided in the Holder Binding JWT.
      // Determine that the Holder Binding JWT is bound to the current transaction and was created for this Verifier (replay
      // protection). This is usually achieved by a nonce and aud field within the Holder Binding JWT.
      val holderVerifier = DefaultJWSVerifierFactory().createJWSVerifier(
        keyBindingJwt.header,
        keyFromHeader(keyBindingJwt.header)
      )
      require(keyBindingJwt.verify(holderVerifier)) {
        throw SignatureException("Verifying the issuerJwt failed: ${keyBindingJwt.serialize()}")
      }

      val nonce = keyBindingJwt.jwtClaimsSet.getClaim("nonce") as? String?
        ?: throw SignatureException("Nonce must be present in holder binding jwt")

      require(nonce == verificationOptions.desiredNonce) {
        throw SignatureException("Nonce found does not match desiredNonce")
      }

      var audienceFound = false
      for (audience in keyBindingJwt.jwtClaimsSet.audience) {
        if (audience == verificationOptions.desiredAudience) {
          audienceFound = true
          break
        }
      }
      require(!audienceFound) {
        throw SignatureException("Desired audience not found")
      }
    }
  }

  private fun keyFromHeader(header: JWSHeader): Key {
    // TODO: replace this with something better, like did resolution. Perhaps make it injectable.
    return header.jwk.toECKey().toECPublicKey()
  }

  /**
   * Returns a set of indices for disclosures contained within this SD-JWT. The
   * indices are selected such that the disclosure's digest is contained inside the [digests] map.
   */
  public fun selectDisclosures(digests: Set<String>): Set<Int> {
    val hashAlg = issuerJwt.jwtClaimsSet.getHashAlg()
    return buildSet {
      for (disclosureAndIndex in disclosures.withIndex()) {
        val disclosure = disclosureAndIndex.value
        if (digests.contains(disclosure.digest(hashAlg))) {
          add(disclosureAndIndex.index)
        }
      }
    }
  }

  /**
   * Returns the digest for the disclosure that matches [name].
   */
  public fun digestsOf(name: String, disclosedValue: Any? = null): String? {
    val hashAlg = issuerJwt.jwtClaimsSet.getHashAlg()
    val objectDisclosure = disclosures.map { it as? ObjectDisclosure }.firstOrNull { it?.claimName == name }
    if (objectDisclosure != null) {
      return objectDisclosure.digest(hashAlg)
    }
    val claim = issuerJwt.jwtClaimsSet.getClaim(name)
    val disclosuresByDigest = disclosures.associateBy { it.digest(hashAlg) }
    if (claim != null && claim is List<*>) {
      for (value in claim) {
        require(value is Map<*, *>)
        val digest = value["..."]
        if (digest is String && (disclosuresByDigest[digest] as ArrayDisclosure?)?.claimValue == disclosedValue) {
          return digest
        }
      }
    }
    return null
  }

  /** Same as [SdJwtUnblinder.unblind]. */
  public fun unblind(): JWTClaimsSet = SdJwtUnblinder().unblind(this.serialize())

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
        input,
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
            claimValue = disclosureElems[2] as Any,
            raw = encodedDisclosure
          )
        }

        2 -> {
          // Create a Disclosure instance
          return ArrayDisclosure(
            salt = disclosureElems[0] as String,
            claimValue = disclosureElems[1] as Any,
            raw = encodedDisclosure
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

