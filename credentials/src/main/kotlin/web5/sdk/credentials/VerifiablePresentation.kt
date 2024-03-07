package web5.sdk.credentials

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import web5.sdk.credentials.util.JwtUtil
import web5.sdk.dids.ChangemeDid
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
@Suppress("UNCHECKED_CAST")
public class VerifiablePresentation internal constructor(public val vpDataModel: VpDataModel) {

  public val verifiableCredential: List<String>
    get() = vpDataModel.toMap()["verifiableCredential"] as List<String>

    public val holder: String
    get() = vpDataModel.holder.toString()

  /**
   * Sign a verifiable presentation using a specified decentralized identifier ([did]) with the private key that pairs
   * with the public key identified by [assertionMethodId].
   *
   * If the [assertionMethodId] is null, the function will attempt to use the first available verification method from
   * the [did]. The result is a String in a JWT format.
   *
   * @param did The [ChangemeDid] used to sign the credential.
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
  public fun sign(did: ChangemeDid, assertionMethodId: String? = null): String {
    val payload = JWTClaimsSet.Builder()
      .issuer(did.uri)
      .issueTime(Date())
      .claim("vp", vpDataModel.toMap())
      .build()

    return JwtUtil.sign(did, assertionMethodId, payload)
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
     * - Verifies that the vcJwts inside the VP are valid
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
      JwtUtil.verify(vpJwt)

      val vp = this.parseJwt(vpJwt)
      vp.verifiableCredential.forEach {
        try {
          VerifiableCredential.verify(it)
        } catch (e: Exception) {
          throw SignatureException("Failed to verify a credential inside of the vp: ${e.message}", e)
        }
      }
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
