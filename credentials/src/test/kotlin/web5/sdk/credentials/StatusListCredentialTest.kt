package web5.sdk.credentials

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpHandler
import com.sun.net.httpserver.HttpServer
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.fullPath
import io.ktor.http.headersOf
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.key.DidKey
import java.io.File
import java.io.OutputStream
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class StatusListCredentialTest {
  @Test
  fun `should parse valid VerifiableCredential from specification example`() {
    val specExampleRevocableVcText = File("src/test/resources/revocable_vc.json").readText()

    val specExampleRevocableVc = VerifiableCredential.fromJson(
      specExampleRevocableVcText
    )

    assertTrue(
      specExampleRevocableVc.vcDataModel.contexts.containsAll(
        listOf(
          URI.create("https://www.w3.org/ns/credentials/v2"),
          URI.create("https://www.w3.org/ns/credentials/examples/v2")
        )
      )
    )

    assertEquals(specExampleRevocableVc.type, "VerifiableCredential")
    assertEquals(specExampleRevocableVc.issuer.toString(), "did:example:12345")
    assertNotNull(specExampleRevocableVc.vcDataModel.credentialStatus)
    assertEquals(specExampleRevocableVc.subject, "did:example:6789")
    assertEquals(specExampleRevocableVc.vcDataModel.credentialSubject.type.toString(), "Person")

    val credentialStatus: StatusList2021Entry =
      StatusList2021Entry.fromJsonObject(specExampleRevocableVc.vcDataModel.credentialStatus.jsonObject)

    assertEquals(credentialStatus.id.toString(), "https://example.com/credentials/status/3#94567")
    assertEquals(credentialStatus.type.toString(), "BitStringStatusListEntry")
    assertEquals(credentialStatus.statusPurpose.toString(), StatusPurpose.REVOCATION.toString().lowercase())
    assertEquals(credentialStatus.statusListIndex, "94567")
    assertEquals(credentialStatus.statusListCredential.toString(), "https://example.com/credentials/status/3")
  }

  @Test
  fun `should create valid VerifiableCredential with a credential status`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("123")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val credWithCredStatus = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus
    )

    assertTrue(
      credWithCredStatus.vcDataModel.contexts.containsAll(
        listOf(
          URI.create("https://www.w3.org/2018/credentials/v1"),
          URI.create("https://w3id.org/vc/status-list/2021/v1")
        )
      )
    )

    assertEquals(credWithCredStatus.type, "StreetCred")
    assertEquals(credWithCredStatus.issuer, issuerDid.uri)
    assertNotNull(credWithCredStatus.vcDataModel.issuanceDate)
    assertNotNull(credWithCredStatus.vcDataModel.credentialStatus)
    assertEquals(credWithCredStatus.vcDataModel.credentialSubject.claims.get("localRespect"), "high")

    val credStatus: StatusList2021Entry =
      StatusList2021Entry.fromJsonObject(credWithCredStatus.vcDataModel.credentialStatus.jsonObject)

    assertEquals(credStatus.id.toString(), "cred-with-status-id")
    assertEquals(credStatus.type.toString(), "StatusList2021Entry")
    assertEquals(credStatus.statusPurpose.toString(), StatusPurpose.REVOCATION.toString().lowercase())
    assertEquals(credStatus.statusListIndex, "123")
    assertEquals(credStatus.statusListCredential.toString(), "https://example.com/credentials/status/3")
  }

  @Test
  fun `should generate StatusListCredential from multiple VerifiableCredentials`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus1 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("123")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc1 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus1
    )

    val credentialStatus2 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("124")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc2 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus2
    )

    val statusListCredential = StatusListCredential.create(
      "revocation-id",
      issuerDid.uri,
      StatusPurpose.REVOCATION,
      listOf(vc1, vc2)
    )

    assertNotNull(statusListCredential)
    assertTrue(
      statusListCredential.vcDataModel.contexts.containsAll(
        listOf(
          URI.create("https://www.w3.org/2018/credentials/v1"),
          URI.create("https://w3id.org/vc/status-list/2021/v1")
        )
      )
    )
    assertTrue(
      statusListCredential.vcDataModel.types.containsAll(
        listOf(
          "VerifiableCredential",
          "StatusList2021Credential"
        )
      )
    )
    assertEquals(statusListCredential.subject, "revocation-id")
    assertEquals(statusListCredential.vcDataModel.credentialSubject.type, "StatusList2021")
    assertEquals(
      "revocation",
      statusListCredential.vcDataModel.credentialSubject.jsonObject["statusPurpose"] as? String?
    )

    // TODO: Check encoding across other sdks and spec - https://github.com/TBD54566975/web5-kt/issues/97
    // assertEquals(
    //  "H4sIAAAAAAAA/2NgQAESAAPT1/8QAAAA",
    //  statusListCredential.vcDataModel.credentialSubject.jsonObject["encodedList"] as? String?
    //)
  }


  @Test
  fun `should fail when generating StatusListCredential with duplicate indexes`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus1 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("123")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc1 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus1
    )

    val credentialStatus2 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("123")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc2 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus2
    )

    val exception = assertThrows<Exception> {
      StatusListCredential.create(
        "revocation-id",
        issuerDid.uri,
        StatusPurpose.REVOCATION,
        listOf(vc1, vc2)
      )
    }

    assertTrue(
      exception
        .message!!.contains("Duplicate entry found with index: 123")
    )
  }

  @Test
  fun `should fail when generating StatusListCredential with negative index`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus1 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("-1")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc1 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus1
    )

    val exception = assertThrows<Exception> {
      StatusListCredential.create(
        "revocation-id",
        issuerDid.uri,
        StatusPurpose.REVOCATION,
        listOf(vc1)
      )
    }

    assertTrue(
      exception
        .message!!.contains("Invalid status list index: -1")
    )
  }

  @Test
  fun `should fail when generating StatusListCredential with an index larger than maximum size`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus1 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex(Int.MAX_VALUE.toString())
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc1 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus1
    )

    val exception = assertThrows<Exception> {
      StatusListCredential.create(
        "revocation-id",
        issuerDid.uri,
        StatusPurpose.REVOCATION,
        listOf(vc1)
      )
    }

    assertTrue(
      exception
        .message!!.contains("Invalid status list index: ${Int.MAX_VALUE}, index is larger than the bitset size")
    )
  }

  @Test
  fun `should fail when generating StatusListCredential invalid issuer uri`() {
    val exception = assertThrows<Exception> {
      StatusListCredential.create(
        "revocation-id",
       "invalid uri",
        StatusPurpose.REVOCATION,
        listOf())
    }

    assertTrue(
      exception
        .message!!.contains("Issuer is not a valid URI")
    )
  }

  @Test
  fun `should fail when generating StatusListCredential invalid statusListCredId uri`() {
    val exception = assertThrows<Exception> {
      StatusListCredential.create(
        "invalid slc id",
        "did:example:123",
        StatusPurpose.REVOCATION,
        listOf())
    }

    assertTrue(
      exception
        .message!!.contains("Status list credential id is not a valid URI")
    )
  }

  @Test
  fun `should validate if a credential exists in the status list`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus1 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("123")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc1 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus1
    )

    val credentialStatus2 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("124")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc2 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus2
    )

    val credentialStatus3 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("125")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc3 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus3
    )

    val statusListCredential =
      StatusListCredential.create(
        "revocation-id",
        issuerDid.uri,
        StatusPurpose.REVOCATION,
        listOf(vc1, vc2)
      )

    val revoked = StatusListCredential.validateCredentialInStatusList(vc1, statusListCredential)
    assertTrue(revoked)

    val revoked2 = StatusListCredential.validateCredentialInStatusList(vc2, statusListCredential)
    assertTrue(revoked2)

    val revoked3 = StatusListCredential.validateCredentialInStatusList(vc3, statusListCredential)
    assertFalse(revoked3)
  }

  @Test
  fun `should asynchronously validate if a credential is in the status list using a mock HTTP client`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus1 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("123")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc1 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus1
    )

    val credentialStatus2 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("124")
      .statusListCredential(URI.create("https://example.com/credentials/status/3"))
      .build()

    val vc2 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus2
    )

    val statusListCredential =
      StatusListCredential.create(
        "revocation-id",
        issuerDid.uri,
        StatusPurpose.REVOCATION,
        listOf(vc1)
      )

    val slcJwt = statusListCredential.sign(issuerDid)
    assertNotNull(slcJwt)

    val mockedHttpClient = HttpClient(MockEngine) {
      engine {
        addHandler { request ->
          when (request.url.fullPath) {
            "/credentials/status/3" -> {
              val responseBody = slcJwt
              respond(responseBody, headers = headersOf("Content-Type", "application/json"))
            }

            else -> error("Unhandled ${request.url.fullPath}")
          }
        }
      }
    }

    val revoked = StatusListCredential.validateCredentialInStatusList(vc1, mockedHttpClient)
    assertTrue(revoked)

    val revoked2 = StatusListCredential.validateCredentialInStatusList(vc2, mockedHttpClient)
    assertFalse(revoked2)
  }

  @Test
  fun `should asynchronously validate if a credential is in the status list using default HTTP client`() {
    // Create and start a server within the test
    val server = HttpServer.create(java.net.InetSocketAddress(1234), 0)

    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus1 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("123")
      .statusListCredential(URI.create("http://localhost:1234"))
      .build()

    val credWithCredStatus1 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus1
    )

    val statusListCredential1 = StatusListCredential.create(
      "http://localhost:1234",
      issuerDid.uri,
      StatusPurpose.REVOCATION,
      listOf(credWithCredStatus1)
    )

    val signedStatusListCredential = statusListCredential1.sign(issuerDid)

    server.createContext("/", object : HttpHandler {
      override fun handle(t: HttpExchange) {
        val response = signedStatusListCredential.toByteArray()
        t.sendResponseHeaders(200, response.size.toLong())
        val os: OutputStream = t.responseBody
        os.write(response)
        os.close()
      }
    })

    try {
      server.executor = null
      server.start()

      val revoked = StatusListCredential.validateCredentialInStatusList(credWithCredStatus1)
      assertEquals(true, revoked)
    } finally {
      server.stop(0)
    }
  }

  @Test
  fun `should 404 because wrong address for status list credential status list using default HTTP client`() {
    // Create and start a server within the test
    val server = HttpServer.create(java.net.InetSocketAddress(1234), 0)

    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val credentialStatus1 = StatusList2021Entry.builder()
      .id(URI.create("cred-with-status-id"))
      .statusPurpose("revocation")
      .statusListIndex("123")
      .statusListCredential(URI.create("http://localhost:4321"))
      .build()

    val credWithCredStatus1 = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      credentialStatus = credentialStatus1
    )

    val statusListCredential1 = StatusListCredential.create(
      "http://localhost:4321",
      issuerDid.uri,
      StatusPurpose.REVOCATION,
      listOf(credWithCredStatus1)
    )

    val signedStatusListCredential = statusListCredential1.sign(issuerDid)

    server.createContext("/", object : HttpHandler {
      override fun handle(t: HttpExchange) {
        val response = signedStatusListCredential.toByteArray()
        t.sendResponseHeaders(200, response.size.toLong())
        val os: OutputStream = t.responseBody
        os.write(response)
        os.close()
      }
    })

    try {
      server.executor = null
      server.start()

      val exception = assertThrows<Exception> {
        StatusListCredential.validateCredentialInStatusList(credWithCredStatus1)
      }

      assertTrue(
        exception
          .message!!.contains("Failed to retrieve VerifiableCredentialType from http://localhost:4321")
      )
    } finally {
      server.stop(0)
    }
  }
}