package web5.credentials

import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.DIDDocument
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.assertThrows
import uniresolver.result.ResolveDataModelResult
import uniresolver.result.ResolveRepresentationResult
import uniresolver.w3c.DIDResolver
import web5.credentials.model.ConstraintsV2
import web5.credentials.model.CredentialSubject
import web5.credentials.model.FieldV2
import web5.credentials.model.InputDescriptorV2
import web5.credentials.model.PresentationDefinitionV2
import web5.credentials.model.VerifiableCredentialType
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
  fun `generate did key returns valid key`() {
    assertContains(DIDKey.generateEd25519().second, "did:key:z6Mk")
  }

  @Test
  fun `creates vc with createVCOptions returns valid vc jwt`() {
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
  fun `creates vc with valid vc builder returns vc jwt`() {
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
  fun `fulfills presentation definition with valid vcjwt`() {
    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(did))
      .claims(mutableMapOf<String, Any>().apply { this["btcAddress"] = "btcAddress123" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(URI.create(did))
      .issuanceDate(Date())
      .build()

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, null, vc)

    val createVpOptions = CreateVpOptions(getPresentationDefinition(), arrayListOf(vcJwt), did)
    val vpJwt: VpJwt = VerifiablePresentation.create(signOptions, createVpOptions)

    assertTrue(VerifiablePresentation.verify(vpJwt, SimpleResolver(didDocument)))
  }

  @Test
  fun `presentation definition is not fulfilled`() {
    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(did))
      .claims(mutableMapOf<String, Any>().apply { this["something"] = "notgood" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(URI.create(did))
      .issuanceDate(Date())
      .build()

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, null, vc)

    val createVpOptions = CreateVpOptions(getPresentationDefinition(), arrayListOf(vcJwt), did)

    val exception = assertThrows<Exception> {
      VerifiablePresentation.create(signOptions, createVpOptions)
    }

    assertTrue(
      exception
        .message?.contains("There are no useable Vcs that correspond to the presentation definition") == true
    )
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

fun getPresentationDefinition(): PresentationDefinitionV2 {
  return PresentationDefinitionV2(
    id = "test-pd-id",
    name = "simple PD",
    purpose = "pd for testing",
    inputDescriptors = listOf(
      InputDescriptorV2(
        id = "whatever",
        purpose = "id for testing",
        constraints = ConstraintsV2(
          fields = listOf(
            FieldV2(
              path = listOf("$.credentialSubject.btcAddress")
            )
          )
        )
      )
    )
  )
}