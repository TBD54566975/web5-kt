package web5.credentials

import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.DIDDocument
import org.junit.jupiter.api.BeforeEach
import uniresolver.result.ResolveDataModelResult
import uniresolver.result.ResolveRepresentationResult
import uniresolver.w3c.DIDResolver
import java.net.URI
import java.util.Base64
import java.util.Date
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SSITest {
  lateinit var signOptions: SignOptions
  lateinit var didKey: Triple<JWK, String, DIDDocument>
  lateinit var did: String
  lateinit var didDocument: DIDDocument

  @BeforeEach
  fun setup() {
    didKey = DIDKey.generateEd25519()
    did = didKey.second
    didDocument = didKey.third

    signOptions = SignOptions(
      kid = "#" + did.split(":")[2],
      issuerDid = did,
      subjectDid = did,
      signerPrivateKey = didKey.first
    )
  }

  @Test
  fun generateReturnsValidKey() {
    assertContains(DIDKey.generateEd25519().second, "did:key:z6Mk")
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
      .id(URI.create(didKey.second))
      .claims(claims)
      .build()

    val vcCreateOptions = CreateVcOptions(
      credentialSubject = credentialSubject,
      issuer = did,
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
      .id(URI.create(did))
      .claims(mutableMapOf<String, Any>().apply { this["firstName"] = "Bobby" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(URI.create(did))
      .issuanceDate(Date())
      .build()

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, null, vc)
    assertTrue(VerifiableCredential.verify(vcJwt, SimpleResolver(didDocument)))
  }

  @Test
  fun `creates a valid VP JWT with valid VC`() {
    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(did))
      .claims(mutableMapOf<String, Any>().apply { this["firstName"] = "Bobby" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(URI.create(did))
      .issuanceDate(Date())
      .build()

    val createVpOptions = CreateVpOptions(arrayListOf(vc), did)
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
