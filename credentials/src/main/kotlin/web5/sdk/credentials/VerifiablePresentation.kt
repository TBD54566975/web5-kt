package web5.sdk.credentials

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import foundation.identity.did.DIDURL
import foundation.identity.did.VerificationMethod
import web5.sdk.common.Convert
import web5.sdk.crypto.Crypto
import web5.sdk.dids.Did
import web5.sdk.dids.DidResolvers
import web5.sdk.dids.findAssertionMethodById
import java.net.URI
import java.security.SignatureException
import java.util.Date
import java.util.UUID

/**
 * Type alias representing the danubetech Verifiable Presentation data model.
 * This typealias simplifies the use of the [com.danubetech.verifiablecredentials.VerifiablePresentation] class.
 */
public typealias VpDataModel = com.danubetech.verifiablecredentials.VerifiablePresentation


/**
 * `VerifiablePresentation` is a tamper-evident presentation encoded in such a way that authorship of the data
 * can be trusted after a process of cryptographic verification.
 * [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/).
 *
 * It provides functionalities to sign, verify, and create presentations, offering a concise API to
 * work with JWT representations of verifiable presentations and ensuring that the signatures
 * and claims within those JWTs can be validated.
 *
 * @property vpDataModel The [vpDataModel] instance representing the core data model of a verifiable presentation.
 */
public class VerifiablePresentation internal constructor(public val vpDataModel: VpDataModel) {

  public val verifiableCredential: List<String>
    get() = vpDataModel.toMap().get("verifiableCredential") as List<String>

    public val holder: String
    get() = vpDataModel.holder.toString()

  /**
   * Sign a verifiable presentation using a specified decentralized identifier ([did]) with the private key that pairs
   * with the public key identified by [assertionMethodId].
   *
   * If the [assertionMethodId] is null, the function will attempt to use the first available verification method from
   * the [did]. The result is a String in a JWT format.
   *
   * @param did The [Did] used to sign the credential.
   * @param assertionMethodId An optional identifier for the assertion method that will be used for verification of the
   *        produced signature.
   * @return The JWT representing the signed verifiable credential.
   *
   * Example:
   * ```
   * val signedVp = verifiablePresentation.sign(myDid)
   * ```
   */
  @JvmOverloads
  public fun sign(did: Did, assertionMethodId: String? = null): String {
    val didResolutionResult = DidResolvers.resolve(did.uri)
    val assertionMethod: VerificationMethod = didResolutionResult.didDocument.findAssertionMethodById(assertionMethodId)

    // TODO: ensure that publicKeyJwk is not null
    val publicKeyJwk = JWK.parse(assertionMethod.publicKeyJwk)
    val keyAlias = did.keyManager.getDeterministicAlias(publicKeyJwk)

    // TODO: figure out how to make more reliable since algorithm is technically not a required property of a JWK
    val algorithm = publicKeyJwk.algorithm
    val jwsAlgorithm = JWSAlgorithm.parse(algorithm.toString())

    val kid = when (assertionMethod.id.isAbsolute) {
      true -> assertionMethod.id.toString()
      false -> "${did.uri}${assertionMethod.id}"
    }

    val jwtHeader = JWSHeader.Builder(jwsAlgorithm)
      .type(JOSEObjectType.JWT)
      .keyID(kid)
      .build()

    val jwtPayload = JWTClaimsSet.Builder()
      .issuer(did.uri)
      .issueTime(Date())
      .claim("vp", vpDataModel.toMap())
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
   * Converts the current object to its JSON representation.
   *
   * @return The JSON representation of the object.
   */
  override fun toString(): String {
    return vpDataModel.toJson()
  }

  public companion object {
    private val objectMapper: ObjectMapper = ObjectMapper().apply {
      registerModule(KotlinModule.Builder().build())
      setSerializationInclusion(JsonInclude.Include.NON_NULL)
    }

    /**
     * Create a [VerifiablePresentation] based on the provided parameters.
     *
     * @param type The type of the presentation, as a [String].
     * @param holder The holder URI of the presentation, as a [String].
     * @param vcJwts The credentials used in the presentation, as a [String].
     * @param additionalData The presentation data, as a generic mapping [Map<String, Any>].
     * @return A [VerifiablePresentation] instance.
     *
     * Example:
     * ```
     *     val vp = VerifiablePresentation.create(
     *       vcJwts = vcJwts,
     *       holder = holderDid.uri,
     *       type = "PresentationSubmission",
     *       additionalData = mapOf("presentation_submission" to presentationSubmission)
     *     )
     * ```
     */
    @JvmOverloads
    public fun create(
      type: String? = null,
      holder: String,
      vcJwts: Iterable<String>,
      additionalData: Map<String, Any>? = null
    ): VerifiablePresentation {
      val vpProperties: Map<String, Any> =
        additionalData?.plus("verifiableCredential" to vcJwts) ?: mapOf("verifiableCredential" to vcJwts)

      val vpDataModel = VpDataModel.builder()
        .id(URI.create("urn:uuid:${UUID.randomUUID()}"))
        .holder(URI.create(holder))
        .properties(vpProperties)
        .apply {
          type?.let { type(it) }
        }
        .build()

      return VerifiablePresentation(vpDataModel)
    }

    /**
     * Verifies the integrity and authenticity of a Verifiable Presentation (VP) encoded as a JSON Web Token (JWT).
     *
     * This function performs several crucial validation steps to ensure the trustworthiness of the provided VP:
     * - Parses and validates the structure of the JWT.
     * - Ensures the presence of critical header elements `alg` and `kid` in the JWT header.
     * - Resolves the Decentralized Identifier (DID) and retrieves the associated DID Document.
     * - Validates the DID and establishes a set of valid verification method IDs.
     * - Identifies the correct Verification Method from the DID Document based on the `kid` parameter.
     * - Verifies the JWT's signature using the public key associated with the Verification Method.
     *
     * If any of these steps fail, the function will throw a [SignatureException] with a message indicating the nature of the failure.
     *
     * @param vpJwt The Verifiable Presentation in JWT format as a [String].
     * @throws SignatureException if the verification fails at any step, providing a message with failure details.
     * @throws IllegalArgumentException if critical JWT header elements are absent.
     *
     * ### Example:
     * ```
     * try {
     *     VerifiablePresentation.verify(signedVpJwt)
     *     println("VP Verification successful!")
     * } catch (e: SignatureException) {
     *     println("VP Verification failed: ${e.message}")
     * }
     * ```
     */
    public fun verify(vpJwt: String) {
      val jwt = JWTParser.parse(vpJwt) as SignedJWT // validates JWT

      require(jwt.header.algorithm != null && jwt.header.keyID != null) {
        "Signature verification failed: Expected JWS header to contain alg and kid"
      }

      val verificationMethodId = jwt.header.keyID
      val parsedDidUrl = DIDURL.fromString(verificationMethodId) // validates vm id which is a DID URL

      val didResolutionResult = DidResolvers.resolve(parsedDidUrl.did.didString)
      if (didResolutionResult.didResolutionMetadata?.error != null) {
        throw SignatureException(
          "Signature verification failed: " +
            "Failed to resolve DID ${parsedDidUrl.did.didString}. " +
            "Error: ${didResolutionResult.didResolutionMetadata?.error}"
        )
      }

      // create a set of possible id matches. the DID spec allows for an id to be the entire `did#fragment`
      // or just `#fragment`. See: https://www.w3.org/TR/did-core/#relative-did-urls.
      // using a set for fast string comparison. DIDs can be lonnng.
      val verificationMethodIds = setOf(parsedDidUrl.didUrlString, "#${parsedDidUrl.fragment}")
      val assertionMethods = didResolutionResult.didDocument.assertionMethodVerificationMethodsDereferenced
      val assertionMethod = assertionMethods?.firstOrNull {
        val id = it.id.toString()
        verificationMethodIds.contains(id)
      }

      if (assertionMethod == null) {
        throw SignatureException(
          "Signature verification failed: Expected kid in JWS header to dereference " +
            "a DID Document Verification Method with an Assertion verification relationship"
        )
      }

      require(assertionMethod.isType("JsonWebKey2020") && assertionMethod.publicKeyJwk != null) {
        throw SignatureException(
          "Signature verification failed: Expected kid in JWS header to dereference " +
            "a DID Document Verification Method of type JsonWebKey2020 with a publicKeyJwk"
        )
      }

      val publicKeyMap = assertionMethod.publicKeyJwk
      val publicKeyJwk = JWK.parse(publicKeyMap)

      val toVerifyBytes = jwt.signingInput
      val signatureBytes = jwt.signature.decode()

      Crypto.verify(publicKeyJwk, toVerifyBytes, signatureBytes, jwt.header.algorithm)
    }

    /**
     * Parses a JWT into a [VerifiablePresentation] instance.
     *
     * @param vpJwt The verifiable credential JWT as a [String].
     * @return A [VerifiablePresentation] instance derived from the JWT.
     *
     * Example:
     * ```
     * val vp = VerifiablePresentation.parseJwt(signedVpJwt)
     * ```
     */
    public fun parseJwt(vpJwt: String): VerifiablePresentation {
      val jwt = JWTParser.parse(vpJwt) as SignedJWT
      val jwtPayload = jwt.payload.toJSONObject()
      val vpDataModelValue = jwtPayload.getOrElse("vp") {
        throw IllegalArgumentException("jwt payload missing vp property")
      }

      @Suppress("UNCHECKED_CAST") // only partially unchecked. can only safely cast to Map<*, *>
      val vpDataModelMap = vpDataModelValue as? Map<String, Any>
        ?: throw IllegalArgumentException("expected vp property in JWT payload to be an object")

      val vpDataModel = VpDataModel.fromMap(vpDataModelMap)

      return VerifiablePresentation(vpDataModel)
    }
  }
}
