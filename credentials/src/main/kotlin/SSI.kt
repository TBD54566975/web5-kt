package web5.credentials

import com.danubetech.verifiablecredentials.jwt.JwtVerifiableCredential
import com.danubetech.verifiablecredentials.jwt.JwtVerifiablePresentation
import com.danubetech.verifiablecredentials.jwt.ToJwtConverter
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import uniresolver.result.ResolveDataModelResult
import uniresolver.w3c.DIDResolver
import java.net.URI
import java.util.Base64
import java.util.Date
import java.util.UUID

public data class SignOptions(
  var kid: String,
  var issuerDid: String,
  var subjectDid: String,
  var signerPrivateKey: JWK
)

// TODO: Implement CredentialSchema,
public data class CreateVcOptions(
  val credentialSubject: CredentialSubject,
  val issuer: String,
  val expirationDate: Date?,
  val credentialStatus: CredentialStatus?,
)

public data class CreateVpOptions(
  // TODO: Add this
  // val presentationDefinition: PresentationDefinitionV2,
  // val verifiableCredentialJwts: List<String>,
  // TODO: remove this for verifiableCredentialJwts instead
  val verifiableCredentials: List<VerifiableCredentialType>,
  val holder: String,
)

public data class DecodedVcJwt(
  val header: Any,
  val payload: Any,
  val signature: String,
)

public typealias VcJwt = String
public typealias VpJwt = String

public class VerifiableCredential private constructor() {
  public companion object {
    @Throws(Exception::class)
    public fun create(
      signOptions: SignOptions,
      createVcOptions: CreateVcOptions?,
      verifiableCredential: VerifiableCredentialType?,
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

    @Throws(Exception::class)
    public fun validatePayload(vc: VerifiableCredentialType) {
      Validation.validate(vc)
    }

    @Throws(Exception::class)
    public fun verify(vcJWT: String, resolver: DIDResolver): Boolean {
      require(vcJWT.isNotEmpty())

      val publicKeyJWK = issuerPublicJWK(vcJWT, resolver)

      val verifier = JWSObject.parse(vcJWT).header.algorithm.toVerifier(publicKeyJWK)

      return JwtVerifiableCredential.fromCompactSerialization(vcJWT).jwsObject.verify(verifier)
    }

    public fun decode(vcJWT: VcJwt): DecodedVcJwt {
      val (encodedHeader, encodedPayload, encodedSignature) = vcJWT.split('.')

      return DecodedVcJwt(
        header = String(Base64.getDecoder().decode(encodedHeader)),
        payload = String(Base64.getDecoder().decode(encodedPayload)),
        signature = encodedSignature
      )
    }
  }
}

private fun JWSAlgorithm.toVerifier(publicKeyJWK: JWK): JWSVerifier? {
  return when (this) {
    JWSAlgorithm.EdDSA -> Ed25519Verifier(publicKeyJWK.toOctetKeyPair())
    JWSAlgorithm.ES256K -> ECDSAVerifier(publicKeyJWK.toECKey())
    JWSAlgorithm.ES256 -> ECDSAVerifier(publicKeyJWK.toECKey())
    JWSAlgorithm.ES384 -> ECDSAVerifier(publicKeyJWK.toECKey())
    JWSAlgorithm.ES512 -> ECDSAVerifier(publicKeyJWK.toECKey())
    else -> null
  }
}

public class VerifiablePresentation private constructor() {
  public companion object {
    public fun create(signOptions: SignOptions, createVpOptions: CreateVpOptions): VpJwt {

      // TODO change to be more than one VC
      val vp: VerifiablePresentationType = VerifiablePresentationType.builder()
        .verifiableCredential(createVpOptions.verifiableCredentials[0])
        .holder(URI.create(createVpOptions.holder))
        .build()

      return ToJwtConverter.toJwtVerifiablePresentation(vp)
        .sign_Ed25519_EdDSA(signOptions.signerPrivateKey.toOctetKeyPair(), signOptions.kid, false)
    }

    public fun verify(vpJWT: String, resolver: DIDResolver): Boolean {
      val publicKeyJWK = issuerPublicJWK(vpJWT, resolver)
      require(!publicKeyJWK.isPrivate)
      require(vpJWT.isNotEmpty())
      return JwtVerifiablePresentation.fromCompactSerialization(vpJWT)
        .verify_Ed25519_EdDSA(publicKeyJWK.toOctetKeyPair())
    }
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