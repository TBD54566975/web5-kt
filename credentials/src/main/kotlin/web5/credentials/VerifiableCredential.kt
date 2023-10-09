package web5.credentials

import com.danubetech.verifiablecredentials.CredentialSubject
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import web5.sdk.common.Convert
import web5.sdk.crypto.Crypto
import web5.sdk.dids.Did
import web5.sdk.dids.DidResolvers
import java.net.URI
import com.danubetech.verifiablecredentials.VerifiableCredential as VcDataModel

/**
 * `VerifiableCredential` represents a digitally verifiable credential according to the
 * [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/).
 *
 * It provides functionalities to sign, verify, and create credentials, offering a concise API to
 * work with JWT representations of verifiable credentials and ensuring that the signatures
 * and claims within those JWTs can be validated.
 *
 * @property vcDataModel The [VcDataModel] instance representing the core data model of a verifiable credential.
 */
public class VerifiableCredential(private val vcDataModel: VcDataModel) {
  /**
   * Sign a verifiable credential using a specified decentralized identifier ([did]) and an optional key alias ([keyAlias]).
   *
   * If the [keyAlias] is null, the function will attempt to use the first available verification method from the [did].
   * The result is a String in a JWT format.
   *
   * @param did The [Did] used to sign the credential.
   * @param keyAlias An optional alias for the key used to sign the credential.
   * @return The JWT representing the signed verifiable credential.
   *
   * Example:
   * ```
   * val signedVc = verifiableCredential.sign(myDid)
   * ```
   */
  public fun sign(did: Did, keyAlias: String? = null): String {
    val keyAliaz = keyAlias ?: run {
      val didResolutionResult = DidResolvers.resolve(did.uri)
      val verificationMethod = didResolutionResult.didDocument.allVerificationMethods[0]

      require(verificationMethod != null) { "no key alias found" }

      verificationMethod.id.toString()
    }

    // TODO: figure out how to make more reliable since algorithm is technically not a required property of a JWK
    // BUT we always include it in our JWKs
    val publicKey = did.keyManager.getPublicKey(keyAliaz)
    val algorithm = publicKey.algorithm
    val jwsAlgorithm = JWSAlgorithm.parse(algorithm.toString())

    val jwtHeader = JWSHeader.Builder(jwsAlgorithm)
      .keyID(keyAlias)
      .build()

    val jwtPayload = JWTClaimsSet.Builder()
      .subject(vcDataModel.credentialSubject.id.toString())
      .claim("vc", vcDataModel.toMap())
      .build()

    val jwtObject = SignedJWT(jwtHeader, jwtPayload)
    val toSign = jwtObject.signingInput

    val signatureBytes = did.keyManager.sign(keyAliaz, toSign)

    val base64UrlEncodedSignature = Base64URL(Convert(signatureBytes).toBase64Url(padding = false))
    val base64UrlEncodedHeader = jwtHeader.toBase64URL()
    val base64UrlEncodedPayload = jwtPayload.toPayload().toBase64URL()

    return "$base64UrlEncodedHeader.$base64UrlEncodedPayload.$base64UrlEncodedSignature"
  }

  /**
   * Sign a verifiable credential using a specified decentralized identifier ([did]) and an optional key alias ([keyAlias]).
   *
   * If the [keyAlias] is null, the function will attempt to use the first available verification method from the [did].
   * The result is a String in a JWT format.
   *
   * @param did The [Did] used to sign the credential.
   * @param keyAlias An optional alias for the key used to sign the credential.
   * @return The JWT representing the signed verifiable credential.
   *
   * Example:
   * ```
   * val jwt = verifiableCredential.sign(myDid)
   * ```
   */
  override fun toString(): String {
    return vcDataModel.toJson()
  }

  public companion object {
    private val objectMapper: ObjectMapper = ObjectMapper().apply {
      registerModule(KotlinModule.Builder().build())
      setSerializationInclusion(JsonInclude.Include.NON_NULL)
    }

    /**
     * Create a [VerifiableCredential] based on the provided parameters.
     *
     * @param type The type of the credential, as a [String].
     * @param issuer The issuer URI of the credential, as a [String].
     * @param subject The subject URI of the credential, as a [String].
     * @param data The credential data, as a generic type [T].
     * @return A [VerifiableCredential] instance.
     *
     * Example:
     * ```
     * val vc = VerifiableCredential.create("ExampleCredential", "http://example.com/issuers/1", "http://example.com/subjects/1", myData)
     * ```
     */
    public fun <T> create(type: String, issuer: String, subject: String, data: T): VerifiableCredential {
      val jsonData: JsonNode = objectMapper.valueToTree(data)
      @Suppress("UNCHECKED_CAST")
      val mapData = objectMapper.treeToValue(jsonData, Map::class.java) as MutableMap<String, Any>

      val credentialSubject = CredentialSubject.builder()
        .id(URI.create(subject))
        .claims(mapData)
        .build()

      val vcDataModel = VcDataModel.builder()
        .type(type)
        .issuer(URI.create(issuer))
        .credentialSubject(credentialSubject)
        .build()

      return VerifiableCredential(vcDataModel)
    }

    /**
     * Verifies the integrity and authenticity of a verifiable credential JWT.
     *
     * Validates the signature and ensures the credential has not been tampered with.
     *
     * @param vcJwt The verifiable credential JWT as a [String].
     *
     * Example:
     * ```
     * val vc = VerifiableCredential.verify(signedVcJwt)
     * ```
     */
    public fun verify(vcJwt: String) {
      val jwt = JWTParser.parse(vcJwt) as SignedJWT
      val verificationMethodId = jwt.header.keyID

      val (did, _) = verificationMethodId.split("#")

      val didResolutionResult = DidResolvers.resolve(did)
      val verificationMethod = didResolutionResult.didDocument.allVerificationMethodsAsMap
        .getOrElse(URI.create(verificationMethodId)) {
          throw IllegalArgumentException("Verification method not found.")
        }

      val publicKeyMap = verificationMethod.publicKeyJwk
      val publicKeyJwk = JWK.parse(publicKeyMap)

      val toVerifyBytes = jwt.signingInput
      val signatureBytes = jwt.signature.decode()

      Crypto.verify(publicKeyJwk, toVerifyBytes, signatureBytes, jwt.header.algorithm)
    }

    /**
     * Parses a JWT into a [VerifiableCredential] instance.
     *
     * @param vcJwt The verifiable credential JWT as a [String].
     * @return A [VerifiableCredential] instance derived from the JWT.
     *
     * Example:
     * ```
     * val vc = VerifiableCredential.parseJwt(signedVcJwt)
     * ```
     */
    public fun parseJwt(vcJwt: String): VerifiableCredential {
      val jwt = JWTParser.parse(vcJwt) as SignedJWT
      val jwtPayload = jwt.payload.toJSONObject()
      val vcDataModelMap = jwtPayload.getOrElse("vc") {
        throw IllegalArgumentException("jwt missing vc object in payload")
      }

      @Suppress("UNCHECKED_CAST")
      val vcDataModel = VcDataModel.fromMap(vcDataModelMap as Map<String, Any>)

      return VerifiableCredential(vcDataModel)
    }
  }
}