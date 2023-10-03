package web5.credentials

import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.DIDDocument
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.assertThrows
import web5.credentials.model.CredentialSubject
import web5.credentials.model.StatusList2021Entry
import web5.credentials.model.VerifiableCredentialType
import java.net.URI
import java.util.Date
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SSICredStatusListTest {
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
  fun `valid credential with credentialStatus`() {
    val testCredJwt1 = createTestCredWithStatus(
      did,
      "test-subject-id-1",
      mapOf("firstName" to "Bobby"),
      "123"
    )

    val credWithCredStatus = VerifiableCredential.fromJwt(testCredJwt1)

    assertTrue(
      credWithCredStatus.contexts.containsAll(
        listOf(
          URI.create("https://www.w3.org/2018/credentials/v1"),
          URI.create("https://w3id.org/vc/status-list/2021/v1")
        )
      )
    )

    assertEquals(credWithCredStatus.type, "VerifiableCredential")
    assertEquals(credWithCredStatus.issuer.toString(), did)
    assertNotNull(credWithCredStatus.issuanceDate)
    assertNotNull(credWithCredStatus.credentialStatus)
    assertEquals(credWithCredStatus.credentialSubject.claims.get("firstName"), "Bobby")

    val credentialStatus: StatusList2021Entry =
      StatusList2021Entry.fromJsonObject(credWithCredStatus.credentialStatus.jsonObject)

    assertEquals(credentialStatus.id.toString(), "cred-with-status-id")
    assertEquals(credentialStatus.type.toString(), "StatusList2021Entry")
    assertEquals(credentialStatus.statusPurpose.toString(), "revocation")
    assertEquals(credentialStatus.statusListIndex, "123")
    assertEquals(credentialStatus.statusListCredential.toString(), "status-list-cred-id")
  }

  @Test
  fun `happy path generation`() {
    val revocationID = "revocation-id"
    val testIssuer = did

    val testCred1 = createTestCredWithStatus(
      did,
      "test-subject-id-1",
      mapOf("firstName" to "Bobby"),
      "123"
    )

    val testCred2 = createTestCredWithStatus(
      did,
      "test-subject-id-2",
      mapOf("firstName" to "Joe"),
      "124"
    )

    val statusListCredentialJwt =
      VerifiableCredential.generateStatusList2021Credential(
        signOptions,
        revocationID,
        testIssuer,
        "revocation",
        listOf(testCred1, testCred2)
      )

    val statusListCredential = VerifiableCredential.fromJwt(statusListCredentialJwt)

    assertNotNull(statusListCredential)
    assertTrue(
      statusListCredential.contexts.containsAll(
        listOf(
          URI.create("https://www.w3.org/2018/credentials/v1"),
          URI.create("https://w3id.org/vc/status-list/2021/v1")
        )
      )
    )
    assertTrue(
      statusListCredential.types.containsAll(
        listOf(
          "VerifiableCredential",
          "StatusList2021Credential"
        )
      )
    )
    assertEquals(statusListCredential.credentialSubject.id, URI.create(revocationID))
    assertEquals(statusListCredential.credentialSubject.type, "StatusList2021")
    assertEquals(
      "revocation",
      statusListCredential.credentialSubject.jsonObject["statusPurpose"] as? String?
    )
    assertEquals(
      "H4sIAAAAAAAA/2NgQAESAAPT1/8QAAAA",
      statusListCredential.credentialSubject.jsonObject["encodedList"] as? String?
    )
  }

  @Test
  fun `fails when duplicate statusListIndex`() {
    val revocationID = "revocation-id"
    val testIssuer = did

    val testCred1 = createTestCredWithStatus(
      did,
      "test-subject-id-1",
      mapOf("company" to "Block", "website" to "https://block.xyz"),
      "123"
    )

    val testCred2 = createTestCredWithStatus(
      did,
      "test-subject-id-1",
      mapOf("company" to "Block", "website" to "https://block.xyz"),
      "123"
    )

    val exception = assertThrows<Exception> {
      VerifiableCredential.generateStatusList2021Credential(
        signOptions,
        revocationID,
        testIssuer,
        "revocation",
        listOf(testCred1, testCred2)
      )
    }

    assertTrue(
      exception
        .message!!.contains("duplicate entry found")
    )
  }

  @Test
  fun `invalid index value`() {
    val revocationID = "revocation-id"
    val testIssuer = did

    val testCred1 = createTestCredWithStatus(
      did,
      "test-subject-id-1",
      mapOf("company" to "Block", "website" to "https://block.xyz"),
      "-1"
    )

    val exception = assertThrows<Exception> {
      VerifiableCredential.generateStatusList2021Credential(
        signOptions,
        revocationID,
        testIssuer,
        "revocation",
        listOf(testCred1)
      )
    }

    assertTrue(
      exception
        .message!!.contains("invalid status list index")
    )
  }

  @Test
  fun `validate credential exists in status cred list`() {
    val revocationID = "revocation-id"
    val testIssuer = did
    
    val testCred1 = createTestCredWithStatus(
      did,
      "test-subject-id-1",
      mapOf("company" to "Block", "website" to "https://block.xyz"),
      "123"
    )

    val testCred2 = createTestCredWithStatus(
      did,
      "test-subject-id-1",
      mapOf("company" to "Block", "website" to "https://block.xyz"),
      "124"
    )

    val testCred3 = createTestCredWithStatus(
      did,
      "test-subject-id-1",
      mapOf("company" to "Block", "website" to "https://block.xyz"),
      "125"
    )

    val statusListCredential =
      VerifiableCredential.generateStatusList2021Credential(
        signOptions,
        revocationID,
        testIssuer,
        "revocation",
        listOf(testCred1, testCred2)
      )


    val revoked = VerifiableCredential.validateCredentialInStatusList(testCred1, statusListCredential)
    assertTrue(revoked)

    val revoked2 = VerifiableCredential.validateCredentialInStatusList(testCred2, statusListCredential)
    assertTrue(revoked2)

    val revoked3 = VerifiableCredential.validateCredentialInStatusList(testCred3, statusListCredential)
    assertFalse(revoked3)
  }

  private fun createTestCredWithStatus(
    issuer: String,
    subjectId: String,
    claims: Map<String, String>,
    statusListIndex: String
  ): VcJwt {

    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(subjectId))
      .claims(claims)
      .build()

    val credentialStatus = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex(statusListIndex)
      .statusListCredential(URI.create("status-list-cred-id"))
      .build()

    val vc = VerifiableCredentialType.builder()
      .contexts(
        listOf(
          URI.create("https://w3id.org/vc/status-list/2021/v1")
        )
      )
      .id(URI.create(UUID.randomUUID().toString()))
      .issuer(URI.create(issuer))
      .issuanceDate(Date())
      .credentialSubject(credentialSubject)
      .credentialStatus(credentialStatus)
      .build()

    return VerifiableCredential.create(signOptions, null, vc)
  }
}
