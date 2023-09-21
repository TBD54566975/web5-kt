package web5.credentials

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
import org.junit.jupiter.api.BeforeEach
import uniresolver.result.ResolveDataModelResult
import uniresolver.result.ResolveRepresentationResult
import uniresolver.w3c.DIDResolver
import web5.dids.CreateDIDKeyOptions
import web5.dids.DIDCreationResult
import web5.dids.DIDKeyMethod
import java.net.URI
import java.util.Base64
import java.util.Date
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SSITest {
  lateinit var signOptions: SignOptions
  lateinit var didKey: DIDCreationResult
  lateinit var privateJWK: JWK
  lateinit var did: DID
  lateinit var didDocument: DIDDocument

  @BeforeEach
  fun setup() {
    privateJWK = OctetKeyPairGenerator(Curve.Ed25519)
      .generate()

    val didCreator = DIDKeyMethod.creator(CreateDIDKeyOptions(privateJWK.toPublicJWK()))
    assertTrue(DIDKeyMethod.authorize(didCreator))
    didKey = didCreator.create()

    did = didKey.did
    didDocument = didKey.document

    signOptions = SignOptions(
      kid = "#" + did.methodSpecificId,
      issuerDid = did.toString(),
      subjectDid = did.toString(),
      signerPrivateKey = privateJWK
    )
  }

  @Test
  fun `creates a VC JWT with CreateVCOptions`() {
    val claims: MutableMap<String, Any> = LinkedHashMap()
    val degree: MutableMap<String, Any> = LinkedHashMap()
    degree["name"] = "Bachelor of Science and Arts"
    degree["type"] = "BachelorDegree"
    claims["college"] = "Test University"
    claims["degree"] = degree

    val credentialSubject = CredentialSubject.builder()
      .id(didKey.did.toUri())
      .claims(claims)
      .build()

    val vcCreateOptions = CreateVcOptions(
      credentialSubject = credentialSubject,
      issuer = did.toString(),
      expirationDate = null,
      credentialStatus = null
    )

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, vcCreateOptions, null)

    assertNotNull(vcJwt)
    assertTrue { vcJwt.split(".").size == 3 }

    val parts = vcJwt.split(".")
    val header = String(Base64.getDecoder().decode(parts[0]))
    val payload = String(Base64.getDecoder().decode(parts[1]))

    // Header Checks
    assertTrue { header.contains("\"alg\":\"") }
    assertTrue { header.contains("\"typ\":\"JWT\"") }

    // Payload Checks
    assertTrue { payload.contains("\"iss\":\"") }
    assertTrue { payload.contains("\"sub\":\"") }

    assertTrue {
      VerifiableCredential.verify(vcJwt, SimpleResolver(didDocument))
    }
  }

  @Test
  fun `creates a valid VC JWT with valid VC builder`() {
    val credentialSubject = CredentialSubject.builder()
      .id(did.toUri())
      .claims(mutableMapOf<String, Any>().apply { this["firstName"] = "Bobby" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(did.toUri())
      .issuanceDate(Date())
      .build()

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, null, vc)
    assertTrue(VerifiableCredential.verify(vcJwt, SimpleResolver(didDocument)))
  }

  @Test
  fun `creates a valid VP JWT with valid VC`() {
    val credentialSubject = CredentialSubject.builder()
      .id(did.toUri())
      .claims(mutableMapOf<String, Any>().apply { this["firstName"] = "Bobby" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(did.toUri())
      .issuanceDate(Date())
      .build()

    val createVpOptions = CreateVpOptions(arrayListOf(vc), did.toString())
    val vpJwt: VpJwt = VerifiablePresentation.create(signOptions, createVpOptions)
    assertTrue(VerifiablePresentation.verify(vpJwt, SimpleResolver(didDocument)))
  }
}

class SimpleResolver(var didDocument: DIDDocument) : DIDResolver {
  override fun resolve(p0: String?, p1: MutableMap<String, Any>?): ResolveDataModelResult {
    return ResolveDataModelResult.build(null, this.didDocument, null)
  }

  override fun resolveRepresentation(p0: String?, p1: MutableMap<String, Any>?): ResolveRepresentationResult {
    return ResolveRepresentationResult.build()
  }
}
