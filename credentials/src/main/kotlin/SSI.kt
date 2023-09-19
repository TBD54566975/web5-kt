package web5.credentials

import com.danubetech.verifiablecredentials.jwt.JwtVerifiableCredential
import com.danubetech.verifiablecredentials.jwt.JwtVerifiablePresentation
import com.danubetech.verifiablecredentials.jwt.ToJwtConverter
import com.identityfoundry.ddi.protocol.multicodec.Multicodec
import com.identityfoundry.ddi.protocol.multicodec.MulticodecEncoder
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
import java.net.URI
import java.util.*

public class DIDKey {
  public companion object {
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

public data class SignOptions(
  var kid: String,
  var issuerDid: String,
  var subjectDid: String,
  var signerPrivateKey: JWK,
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

public class VerifiableCredential {
  public companion object {
    @Throws(Exception::class)
    public fun create(
      signOptions: SignOptions,
      createVcOptions: CreateVcOptions?,
      verifiableCredential: VerifiableCredentialType?,
    ): VcJwt {
      if (createVcOptions != null && verifiableCredential != null) {
        throw Exception("createVcOptions and verifiableCredential are mutually exclusive, either include the full verifiableCredential or the options to create one")
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

      return JwtVerifiableCredential.fromCompactSerialization(vcJWT)
        .verify_Ed25519_EdDSA(publicKeyJWK.toOctetKeyPair())
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

public class VerifiablePresentation {
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