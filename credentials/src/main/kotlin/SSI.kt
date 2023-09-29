package web5.credentials

import com.danubetech.verifiablecredentials.VerifiablePresentation
import com.danubetech.verifiablecredentials.jwt.FromJwtConverter
import com.danubetech.verifiablecredentials.jwt.JwtVerifiableCredential
import com.danubetech.verifiablecredentials.jwt.JwtVerifiablePresentation
import com.danubetech.verifiablecredentials.jwt.ToJwtConverter
import com.identityfoundry.ddi.protocol.multicodec.Multicodec
import com.identityfoundry.ddi.protocol.multicodec.MulticodecEncoder
import com.nfeld.jsonpathkt.JsonPath
import com.nfeld.jsonpathkt.extension.read
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
import foundation.identity.did.VerificationMethod
import io.ipfs.multibase.Multibase
import uniresolver.result.ResolveDataModelResult
import uniresolver.w3c.DIDResolver
import web5.credentials.model.CredentialStatus
import web5.credentials.model.CredentialSubject
import web5.credentials.model.DescriptorMap
import web5.credentials.model.FieldV2
import web5.credentials.model.InputDescriptorV2
import web5.credentials.model.PresentationDefinitionV2
import web5.credentials.model.PresentationSubmission
import web5.credentials.model.VerifiableCredentialType
import web5.credentials.model.VerifiablePresentationType
import java.net.URI
import java.util.Base64
import java.util.Date
import java.util.UUID

/**
 * Represents a utility class for DIDKey operations.
 */
public class DIDKey private constructor() {
  public companion object {
    /**
     * Generates an Ed25519 DIDKey along with its associated JWK, identifier, and DID document.
     *
     * @return A [Triple] containing the JWK, identifier, and DID document.
     */
    public fun generateEd25519(): Triple<JWK, String, DIDDocument> {
      val jwk = OctetKeyPairGenerator(Curve.Ed25519)
        .generate()
      val publicJWK = jwk.toPublicJWK()

      val methodSpecId: String = Multibase.encode(
        Multibase.Base.Base58BTC,
        MulticodecEncoder.encode(Multicodec.ED25519_PUB, publicJWK.decodedX)
      )

      val identifier = "did:key:$methodSpecId"
      val didDocument = createDocument(identifier)

      return Triple(
        jwk,
        identifier,
        didDocument,
      )
    }

    private fun createSignatureMethod(did: DID): VerificationMethod {
      val multibaseValue = did.methodSpecificId
      val decodedMultibase = Multibase.decode(multibaseValue)
      val decodedData = MulticodecEncoder.decode(decodedMultibase)
      val multicodecValue = decodedData.codec
      val rawPublicKeyBytes = decodedData.dataAsBytes

      // The byte len for ed25519-pub
      require(rawPublicKeyBytes.size == 32)

      return VerificationMethod.builder()
        .id(URI.create(did.toUri().toString() + "#$multibaseValue"))
        .type("JsonWebKey2020")
        .controller(did.toUri())
        .publicKeyJwk(encodeJWK(multicodecValue, rawPublicKeyBytes)!!.toJSONObject())
        .build()
    }

    private fun encodeJWK(multicodecValue: Multicodec?, rawPublicKeyBytes: ByteArray?): OctetKeyPair? {
      require(multicodecValue == Multicodec.ED25519_PUB)
      return OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(rawPublicKeyBytes)).build()
    }

    private fun createDocument(identifier: String): DIDDocument {
      val did = DID.fromString(identifier)
      require(did.methodName == "key")
      require(did.methodSpecificId.startsWith('z'))
      val signatureVerificationMethod: VerificationMethod = createSignatureMethod(did)
      val idOnly = VerificationMethod.builder().id(signatureVerificationMethod.id).build()
      return DIDDocument.builder().id(URI.create(identifier))
        .verificationMethod(signatureVerificationMethod)
        .authenticationVerificationMethod(idOnly)
        .assertionMethodVerificationMethod(idOnly)
        .capabilityInvocationVerificationMethod(idOnly)
        .capabilityDelegationVerificationMethod(idOnly)
        .build()
    }

  }
}

/**
 * Represents the signing options required to create verifiable credentials or presentations.
 *
 * @property kid The key identifier for the signing key.
 * @property issuerDid The did for the issuer of the credential or presentation.
 * @property subjectDid The did for the subject of the credential.
 * @property signerPrivateKey The private key used for signing the credential or presentation.
 */
public data class SignOptions(
  var kid: String,
  var issuerDid: String,
  var subjectDid: String,
  var signerPrivateKey: JWK,
)

/**
 * Represents the options required to create a verifiable credential.
 *
 * @property credentialSubject The subject of the credential containing the claims made about the subject.
 * @property issuer The issuer of the verifiable credential.
 * @property expirationDate The expiration date of the verifiable credential.
 * @property credentialStatus The information about the credential status.
 */
public data class CreateVcOptions(
  val credentialSubject: CredentialSubject,
  val issuer: String,
  val expirationDate: Date?,
  val credentialStatus: CredentialStatus?,
  // TODO: Implement CredentialSchema,
)

/**
 * Represents the options required to create a verifiable presentation.
 *
 * @property presentationDefinition The definition describing the requirements of what vcs are needed for the verifiable presentation.
 * @property verifiableCredentialJwts The list of verifiable credentials in JWT format to be included in the presentation.
 * @property holder The decentralized identifier for the holder of the presentation.
 */
public data class CreateVpOptions(
  val presentationDefinition: PresentationDefinitionV2,
  val verifiableCredentialJwts: List<VcJwt>,
  val holder: String, // TODO: Remove this
)

public typealias VcJwt = String
public typealias VpJwt = String

/**
 * Utility class for creating, validating, verifying, and decoding verifiable credentials.
 */
public object VerifiableCredential {

  /**
   * Creates a verifiable credential JWT based on the given signing options, credential creation options, and verifiable credential type.
   *
   * @param signOptions The options required for signing the credential, including the key identifier, issuer DID, subject DID, and signer private key.
   * @param createVcOptions The options required to create a verifiable credential. Either this or [verifiableCredential] must be provided.
   * @param verifiableCredential The verifiable credential to be created. Either this or [createVcOptions] must be provided.
   * @return A [VcJwt] representing the verifiable credential in JWT format.
   * @throws Exception Throws an exception if any validation fails during the creation of the verifiable credential or any other exception occurring during the creation of the credential.
   */
  @Throws(Exception::class)
  public fun create(
    signOptions: SignOptions, createVcOptions: CreateVcOptions?, verifiableCredential: VerifiableCredentialType?,
  ): VcJwt {
    if (createVcOptions != null && verifiableCredential != null) {
      throw Exception(
        "createVcOptions and verifiableCredential are mutually exclusive, either include the full " +
          "verifiableCredential or the options to create one"
      )
    }

    if (createVcOptions == null && verifiableCredential == null) {
      throw Exception("createVcOptions or verifiableCredential must be provided")
    }

    val vc: VerifiableCredentialType = verifiableCredential ?: VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(createVcOptions!!.credentialSubject)
      .issuer(URI.create(createVcOptions.issuer))
      .issuanceDate(Date())
      .apply {
        createVcOptions.expirationDate?.let { expirationDate(it) }
        createVcOptions.credentialStatus?.let { credentialStatus(it) }
      }
      .build()

    this.validatePayload(vc)

    // TODO: This removes issuanceDate which is required https://www.w3.org/TR/vc-data-model/#issuance-date
    return ToJwtConverter.toJwtVerifiableCredential(vc)
      .sign_Ed25519_EdDSA(signOptions.signerPrivateKey.toOctetKeyPair(), signOptions.kid, false)
  }

  /**
   * Validates the payload of a verifiable credential.
   *
   * @param vc The verifiable credential to be validated.
   * @throws Exception Throws an exception if the validation fails, indicating issues with the payload.
   */
  @Throws(Exception::class)
  public fun validatePayload(vc: VerifiableCredentialType) {
    Validation.validate(vc)
  }

  /**
   * Verifies the authenticity of a verifiable credential using its JWT representation and a DID resolver.
   *
   * @param vcJWT The JWT representation of the verifiable credential to be verified.
   * @param resolver The DID resolver used for resolving DID information.
   * @return `true` if the verification succeeds; otherwise, `false`.
   * @throws Exception Throws an exception if the verifications fails.
   */
  @Throws(Exception::class)
  public fun verify(vcJWT: String, resolver: DIDResolver): Boolean {
    require(vcJWT.isNotEmpty())

    val publicKeyJWK = issuerPublicJWK(vcJWT, resolver)

    return JwtVerifiableCredential.fromCompactSerialization(vcJWT)
      .verify_Ed25519_EdDSA(publicKeyJWK.toOctetKeyPair())
  }
}

/**
 * Utility class for creating and verifying verifiable presentations (VPs) in JWT format.
 */
public object VerifiablePresentation {
  /**
   * Creates a verifiable presentation JWT based on the given signing options and presentation creation options.
   *
   * @param signOptions The options required for signing the presentation, including the key identifier, issuer DID, subject DID, and signer private key.
   * @param createVpOptions The options required to create a verifiable presentation, including the presentation definition, list of verifiable credentials in JWT format, and the holder of the presentation.
   * @return A [VpJwt] representing the verifiable presentation in JWT format.
   * @throws Exception if there are no usable verifiable credentials that correspond to the presentation definition or any other exception occurring during the creation of the presentation.
   */
  @Throws(Exception::class)
  public fun create(signOptions: SignOptions, createVpOptions: CreateVpOptions): VpJwt {
    val presentationSubmission = generatePresentationSubmissionFrom(
      createVpOptions.presentationDefinition,
      createVpOptions.verifiableCredentialJwts
    )

    val properties: Map<String, Any> = mapOf(
      "verifiableCredential" to createVpOptions.verifiableCredentialJwts,
      "presentation_submission" to presentationSubmission
    )

    val vp: VerifiablePresentation? = VerifiablePresentationType.builder()
      .properties(properties)
      .holder(URI.create(createVpOptions.holder))
      .context(URI.create("https://identity.foundation/presentation-exchange/submission/v1"))
      .type("PresentationSubmission")
      .build()

    return ToJwtConverter.toJwtVerifiablePresentation(vp)
      .sign_Ed25519_EdDSA(signOptions.signerPrivateKey.toOctetKeyPair(), signOptions.kid, true)
  }

  /**
   * Verifies the authenticity of a verifiable presentation using its JWT representation and a DID resolver.
   *
   * @param vpJWT The JWT representation of the verifiable presentation to be verified.
   * @param resolver The DID resolver used for resolving issuer DID information.
   * @return `true` if the verification succeeds; otherwise, `false`.
   */
  public fun verify(vpJWT: String, resolver: DIDResolver): Boolean {
    val publicKeyJWK = issuerPublicJWK(vpJWT, resolver)
    require(!publicKeyJWK.isPrivate)
    require(vpJWT.isNotEmpty())
    return JwtVerifiablePresentation.fromCompactSerialization(vpJWT)
      .verify_Ed25519_EdDSA(publicKeyJWK.toOctetKeyPair())
  }

  /**
   * The selectFrom method is a helper function that helps filter out the verifiable credentials which can not be selected and returns
   * the selectable credentials.
   *
   * @param presentationDefinition definition of what is expected in the presentation.
   * @param vcJwts verifiable credentials are the credentials from wallet provided to the library to find selectable credentials.
   *
   * @return the selectable credentials.
   */
  @Throws(Exception::class)
  public fun selectFrom(presentationDefinition: PresentationDefinitionV2, vcJwts: List<VcJwt>): List<VcJwt> {
    val selectableCredentials = mutableListOf<VcJwt>()

    if (!presentationDefinition.submissionRequirements.isNullOrEmpty()) {
      throw NotImplementedError("Presentation Definition's Submission Requirements feature is not implemented")
    }

    for (inputDescriptor: InputDescriptorV2 in presentationDefinition.inputDescriptors) {
      // Fields Processing
      if (inputDescriptor.constraints.fields!!.isNotEmpty()) {
        for (vcJwt: VcJwt in vcJwts) {

          val vc: VerifiableCredentialType =
            FromJwtConverter.fromJwtVerifiableCredential(JwtVerifiableCredential.fromCompactSerialization(vcJwt))

          var fieldMatch = false

          for (field: FieldV2 in inputDescriptor.constraints.fields) {

            // Optional fields are not needed to complete the required fields in the presentation definition
            if (field.optional != null && field.optional) {
              continue
            }

            for (jsonPathResult: String in field.path.mapNotNull { evaluateJsonPath(vc, it) }) {
              if (field.filter != null) {
                throw NotImplementedError("Field Filter is not implemented")
              } else {
                fieldMatch = true
                break
              }
            }
          }

          if (fieldMatch) {
            selectableCredentials.add(vcJwt)
          }
        }
      }
    }

    return selectableCredentials
  }

  /**
   * Validates a list of Verifiable Credentials (VcJwts) against a presentation definition and generates a presentation submission
   *
   * This method checks the presentation definition and the list of Verifiable Credentials to ensure
   * that the required fields in the definition are satisfied by the provided credentials.
   *
   * Currently, if the presentation definition contains submission requirements, or if any required field in an input
   * descriptor is not satisfied by the provided credentials, an exception is thrown.
   *
   * A compliant presentation submission is returned
   *
   * ### Throws
   * - [NotImplementedError] if the Presentation Definition contains Submission Requirements or if a Field Filter is implemented.
   * - [Exception] if any required field is not satisfied in the given InputDescriptor.
   *
   * @param presentationDefinition The [PresentationDefinitionV2] object representing the presentation's definition.
   * @param vcJwts The list of [VcJwt] representing the Verifiable Credentials to be validated against the presentation definition.
   * @throws Exception If a required field is not satisfied in a given InputDescriptor.
   * @return the generated presentation submission.
   */
  @Throws(Exception::class)
  private fun generatePresentationSubmissionFrom(
    presentationDefinition: PresentationDefinitionV2,
    vcJwts: List<VcJwt>
  ): PresentationSubmission {
    if (!presentationDefinition.submissionRequirements.isNullOrEmpty()) {
      throw NotImplementedError("Presentation Definition's Submission Requirements feature is not implemented")
    }

    val descriptorMapList = mutableListOf<DescriptorMap>()

    for (inputDescriptor: InputDescriptorV2 in presentationDefinition.inputDescriptors) {
      if (inputDescriptor.constraints.fields!!.isNotEmpty()) {
        for (field: FieldV2 in inputDescriptor.constraints.fields) {
          if (field.optional == true) continue // Skip optional fields

          var fieldMatch = false
          for ((vcIndex, vcJwt) in vcJwts.withIndex()) {
            val vc: VerifiableCredentialType =
              FromJwtConverter.fromJwtVerifiableCredential(JwtVerifiableCredential.fromCompactSerialization(vcJwt))

            for (path: String in field.path) {
              val jsonPathResult = evaluateJsonPath(vc, path)
              if (jsonPathResult != null) {
                if (field.filter != null) {
                  throw NotImplementedError("Field Filter is not implemented")
                } else {
                  fieldMatch = true
                  descriptorMapList.add(
                    DescriptorMap(
                      id = inputDescriptor.id,
                      path = "$.verifiableCredential[$vcIndex]",
                      format = "jwt_vc",
                      // TODO: Support pathNested
                    )
                  )
                  break
                }
              }
            }
            if (fieldMatch) break // Exit the loop once a match is found for the field
          }

          if (!fieldMatch) {
            throw Exception("Required field ${field.id} is not satisfied in InputDescriptor ${inputDescriptor.id}")
          }
        }
      }
    }

    return PresentationSubmission(
      id = UUID.randomUUID().toString(),
      definitionId = presentationDefinition.id,
      descriptorMap = descriptorMapList
    )
  }
}


private fun issuerPublicJWK(vcJWT: String, resolver: DIDResolver): JWK {
  val signedJWT = SignedJWT.parse(vcJWT)
  val jwsHeader = signedJWT.header
  val kid = jwsHeader.keyID
  val issuer: String = signedJWT.jwtClaimsSet.issuer

  val result: ResolveDataModelResult = resolver.resolve(issuer, null)

  val publicKeyJwkMap = result.didDocument.verificationMethods.first {
    it.id.toString().contains(kid)
  }.publicKeyJwk

  val publicKeyJWK = JWK.parse(publicKeyJwkMap)
  return publicKeyJWK
}

private fun evaluateJsonPath(vc: VerifiableCredentialType, path: String): String? {
  val vcJsonString: String = vc.toJson()
  return JsonPath.parse(vcJsonString)?.read<String>(path)
}