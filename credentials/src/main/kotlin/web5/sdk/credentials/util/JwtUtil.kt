package web5.sdk.credentials.util

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import web5.sdk.common.Convert
import web5.sdk.crypto.Crypto
import web5.sdk.dids.Did
import web5.sdk.dids.DidResolvers
import web5.sdk.dids.exceptions.DidResolutionException
import web5.sdk.dids.exceptions.PublicKeyJwkMissingException
import java.net.URI
import java.security.SignatureException

private const val JsonWebKey2020 = "JsonWebKey2020"
private const val JsonWebKey = "JsonWebKey"

/**
 * Util class for common shared JWT methods.
 */
public object JwtUtil {
  /**
   * Sign a jwt payload using a specified decentralized identifier ([did]) with the private key that pairs
   * with the public key identified by [assertionMethodId].
   *
   * If the [assertionMethodId] is null, the function will attempt to use the first available verification method from
   * the [did]. The result is a String in a JWT format.
   *
   * @param did The [Did] used to sign the credential.
   * @param assertionMethodId An optional identifier for the assertion method
   *        that will be used for verification of the produced signature.
   * @param jwtPayload the payload that is getting signed by the [Did]
   * @return The JWT representing the signed verifiable credential.
   *
   * Example:
   * ```
   * val signedVc = verifiableCredential.sign(myDid)
   * ```
   */
  public fun sign(did: Did, assertionMethodId: String?, jwtPayload: JWTClaimsSet): String {
    val didResolutionResult = DidResolvers.resolve(did.uri)
    val didDocument = didResolutionResult.didDocument
    if (didResolutionResult.didResolutionMetadata.error != null || didDocument == null) {
      throw DidResolutionException(
        "Signature verification failed: " +
          "Failed to resolve DID ${did.uri}. " +
          "Error: ${didResolutionResult.didResolutionMetadata.error}"
      )
    }

    val assertionMethod = didDocument.findAssertionMethodById(assertionMethodId)

    val publicKeyJwk = assertionMethod.publicKeyJwk ?: throw PublicKeyJwkMissingException("publicKeyJwk is null.")
    val keyAlias = did.keyManager.getDeterministicAlias(publicKeyJwk)

    // TODO: figure out how to make more reliable since algorithm is technically not a required property of a JWK
    val algorithm = publicKeyJwk.algorithm
    val jwsAlgorithm = JWSAlgorithm.parse(algorithm.toString())

    val kid = when (URI.create(assertionMethod.id).isAbsolute) {
      true -> assertionMethod.id
      false -> "${did.uri}${assertionMethod.id}"
    }

    val jwtHeader = JWSHeader.Builder(jwsAlgorithm)
      .type(JOSEObjectType.JWT)
      .keyID(kid)
      .build()

    val jwtObject = SignedJWT(jwtHeader, jwtPayload)
    val toSign = jwtObject.signingInput
    val signatureBytes = did.keyManager.sign(keyAlias, toSign)

    val base64UrlEncodedHeader = jwtHeader.toBase64URL()
    val base64UrlEncodedPayload = jwtPayload.toPayload().toBase64URL()
    val base64UrlEncodedSignature = Base64URL(Convert(signatureBytes).toBase64Url(padding = false))

    return "$base64UrlEncodedHeader.$base64UrlEncodedPayload.$base64UrlEncodedSignature"
  }

  /**
   * Verifies the integrity and authenticity of a JSON Web Token (JWT).
   *
   * This function performs several crucial validation steps to ensure the trustworthiness of the provided VC:
   * - Parses and validates the structure of the JWT.
   * - Ensures the presence of critical header elements `alg` and `kid` in the JWT header.
   * - Resolves the Decentralized Identifier (DID) and retrieves the associated DID Document.
   * - Validates the DID and establishes a set of valid verification method IDs.
   * - Identifies the correct Verification Method from the DID Document based on the `kid` parameter.
   * - Verifies the JWT's signature using the public key associated with the Verification Method.
   *
   * If any of these steps fail, the function will throw a [SignatureException] with a message indicating the nature of the failure.
   *
   * @param jwtString The JWT as a [String].
   * @throws SignatureException if the verification fails at any step, providing a message with failure details.
   * @throws IllegalArgumentException if critical JWT header elements are absent.
   */
  public fun verify(jwtString: String) {
    val jwt = JWTParser.parse(jwtString) as SignedJWT // validates JWT

    require(jwt.header.algorithm != null && jwt.header.keyID != null) {
      "Signature verification failed: Expected JWS header to contain alg and kid"
    }

    val verificationMethodId = jwt.header.keyID
    val verificationMethodIdParseResult = parseVerificationMethodId(verificationMethodId)

    val didResolutionResult = DidResolvers.resolve(verificationMethodIdParseResult.didUrlString)
    if (didResolutionResult.didResolutionMetadata.error != null) {
      throw SignatureException(
        "Signature verification failed: " +
          "Failed to resolve DID ${verificationMethodIdParseResult}. " +
          "Error: ${didResolutionResult.didResolutionMetadata.error}"
      )
    }

    // create a set of possible id matches. the DID spec allows for an id to be the entire `did#fragment`
    // or just `#fragment`. See: https://www.w3.org/TR/did-core/#relative-did-urls.
    // using a set for fast string comparison. DIDs can be lonnng.
    val verificationMethodIds = setOf(verificationMethodIdParseResult.didUrlString, "#${verificationMethodIdParseResult.fragment}")
    val assertionMethods = didResolutionResult.didDocument?.assertionMethodVerificationMethodsDereferenced
    val assertionMethod = assertionMethods?.firstOrNull {
      val id = it.id
      verificationMethodIds.contains(id)
    }
      ?: throw SignatureException(
        "Signature verification failed: Expected kid in JWS header to dereference " +
          "a DID Document Verification Method with an Assertion verification relationship"
      )

    require((assertionMethod.isType(JsonWebKey2020) || assertionMethod.isType(JsonWebKey))  &&
      assertionMethod.publicKeyJwk != null) {
      throw SignatureException(
        "Signature verification failed: Expected kid in JWS header to dereference " +
          "a DID Document Verification Method of type $JsonWebKey2020 or $JsonWebKey with a publicKeyJwk"
      )
    }

    val publicKeyJwk = assertionMethod.publicKeyJwk ?: throw PublicKeyJwkMissingException("publicKeyJwk is null")
    val toVerifyBytes = jwt.signingInput
    val signatureBytes = jwt.signature.decode()

    Crypto.verify(
      publicKeyJwk,
      toVerifyBytes,
      signatureBytes
    )
  }

  private fun parseVerificationMethodId(verificationMethodId: String): ParsedVerificationMethodId {

    val verificationMethodIdArray = verificationMethodId.split("#")
    require(verificationMethodIdArray.size == 2) {
      "Invalid verification method id: $verificationMethodId"
    }
    return ParsedVerificationMethodId(verificationMethodIdArray[0], verificationMethodIdArray[1])
  }

  private data class ParsedVerificationMethodId(val didUrlString: String, val fragment: String)

}
