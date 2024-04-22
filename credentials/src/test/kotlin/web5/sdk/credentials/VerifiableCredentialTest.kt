package web5.sdk.credentials

import com.danubetech.verifiablecredentials.credentialstatus.CredentialStatus
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.exc.MismatchedInputException
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.common.Convert
import web5.sdk.common.Json
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.AwsKeyManager
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.Jwa
import web5.sdk.dids.did.PortableDid
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.methods.dht.CreateDidDhtOptions
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.jwk.DidJwk
import web5.sdk.dids.methods.key.DidKey
import web5.sdk.jose.jws.JwsHeader
import web5.sdk.jose.jwt.Jwt
import web5.sdk.jose.jwt.JwtClaimsSet
import web5.sdk.testing.TestVectors
import java.io.File
import java.net.URI
import java.security.SignatureException
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Calendar
import java.util.Date
import kotlin.test.Ignore
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull

data class StreetCredibility(val localRespect: String, val legit: Boolean)
class VerifiableCredentialTest {
  @Test
  @Ignore("Testing with a prev created ion did")
  fun `create a vc with a previously created DID in the key manager`() {
    val keyManager = AwsKeyManager()
    val issuerDid = DidDht.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true)
    )

    val vcJwt = vc.sign(issuerDid)

    assertDoesNotThrow {
      VerifiableCredential.verify(vcJwt)
    }
  }

  @Test
  fun `create works`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true)
    )

    assertNotNull(vc)
    assertEquals(vc.type, "StreetCred")
    assertEquals(vc.subject, holderDid.uri)
    assertEquals(vc.issuer, issuerDid.uri)
    assertEquals(vc.vcDataModel.credentialSubject.id.toString(), holderDid.uri)
    assertEquals(vc.vcDataModel.credentialSubject.claims.get("localRespect"), "high")
    assertEquals(vc.vcDataModel.credentialSubject.claims.get("legit"), true)
  }

  @Test
  fun `create throws if data cannot be parsed into a json object`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val exception = assertThrows(IllegalArgumentException::class.java) {
      VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = "trials & tribulations"
      )
    }

    // Optionally, further verify the exception (e.g., check the message)
    assertEquals("expected data to be parseable into a JSON object", exception.message)
  }

  @Test
  fun `verify does not throw an exception if vc is legit`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidJwk.create(keyManager)
    val holderDid = DidJwk.create(keyManager)

    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true)
    )

    val vcJwt = vc.sign(issuerDid)
    VerifiableCredential.verify(vcJwt)
  }

  @Test
  fun `verify throws if it is the wrong issuer that signed the vc`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidJwk.create(keyManager)
    val holderDid = DidJwk.create(keyManager)

    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = "did:fakeissuer:123",
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true)
    )

    val vcJwt = vc.sign(issuerDid)

    assertFails("should fail with fake issuer") {
      VerifiableCredential.verify(vcJwt)
    }
  }

  @Test
  fun `verify does not throw an exception with vc with evidence`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidJwk.create(keyManager)
    val holderDid = DidJwk.create(keyManager)

    val evidence = listOf(
      mapOf(
        "id" to "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
        "type" to listOf("DocumentVerification"),
        "verifier" to "https://example.edu/issuers/14",
        "evidenceDocument" to "DriversLicense",
        "subjectPresence" to "Physical",
        "documentPresence" to "Physical",
        "licenseNumber" to "123AB4567"
      )
    )

    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true),
      evidence = evidence
    )

    assertEquals(vc.evidence, evidence)
    val vcJwt = vc.sign(issuerDid)
    VerifiableCredential.verify(vcJwt)

    val parsedVc = VerifiableCredential.parseJwt(vcJwt)
    assertEquals(parsedVc.evidence, evidence)
  }

  data class KnownCustomerCredential(val id: String, val country_of_residence: String, val tier: String)

@Test
fun `kyc credential verify does not throw an exception if vc is legit`() {
  val keyManager = InMemoryKeyManager()
  val issuerDid = DidJwk.create(keyManager)
  val subjectDid = DidJwk.create(keyManager)

  val expirationCalendar = Calendar.getInstance().apply {
    set(2055, Calendar.DECEMBER, 21) // Note: Calendar months are zero-based in Java/Kotlin
  }

  val expectedEvidence = listOf(
    mapOf("kind" to "document_verification", "checks" to listOf("passport", "utility_bill")),
    mapOf("kind" to "sanctions_check", "checks" to listOf("daily"))
  )


  val vc = VerifiableCredential.create(
    type = "KnowYourCustomerCred",
    issuer = issuerDid.uri,
    subject = subjectDid.uri,
    issuanceDate = Calendar.getInstance().time, // For the current time
    expirationDate = expirationCalendar.time,
    data = KnownCustomerCredential(id = subjectDid.uri, country_of_residence = "US", tier = "Tier 1"),
    credentialSchema = CredentialSchema(
      id = "https://schema.org/PFI",
      type = "JsonSchema"
    ),
    evidence = expectedEvidence
  )

  val vcJwt = vc.sign(issuerDid)
  VerifiableCredential.verify(vcJwt)

  val parsedVc = VerifiableCredential.parseJwt(vcJwt)
  assertEquals(vc.issuer, parsedVc.issuer)
  assertEquals(vc.subject, parsedVc.subject)
  assertEquals(vc.type, parsedVc.type)
  assertEquals(vc.vcDataModel.issuanceDate, parsedVc.vcDataModel.issuanceDate)
  assertEquals(vc.vcDataModel.expirationDate, parsedVc.vcDataModel.expirationDate)
  assertEquals(vc.vcDataModel.credentialSubject, parsedVc.vcDataModel.credentialSubject)
  assertEquals(vc.credentialSchema, parsedVc.credentialSchema)

  assertEquals(vc.evidence, parsedVc.evidence)
}

  @Test
  fun `verify does not throw an exception if vc signed with did dht is legit`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidDht.create(keyManager)
    val holderDid = DidDht.create(keyManager)

    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true)
    )

    val vcJwt = vc.sign(issuerDid)
    VerifiableCredential.verify(vcJwt)
  }

  @Test
  fun `verify handles DIDs without an assertionMethod`() {
    val keyManager = InMemoryKeyManager()

    // Create a DHT DID without an assertionMethod
    val alias = keyManager.generatePrivateKey(AlgorithmId.secp256k1)
    val verificationJwk = keyManager.getPublicKey(alias)

    val verificationMethodsToAdd = listOf(Triple(
      verificationJwk,
      emptyList<Purpose>(),
      "did:web:tbd.website"
    ))
    val issuerDid = DidDht.create(
      InMemoryKeyManager(),
      CreateDidDhtOptions(verificationMethods = verificationMethodsToAdd)
    )

    val header = JwsHeader.Builder()
      .type("JWT")
      .algorithm(Jwa.ES256K.name)
      .keyId(issuerDid.uri)
      .build()
    // A detached payload JWT
    val vcJwt = "${Convert(Json.stringify(header)).toBase64Url()}..fakeSig"

    val exception = assertThrows(SignatureException::class.java) {
      VerifiableCredential.verify(vcJwt)
    }
    assertContains(
      exception.message!!, "Malformed JWT. Invalid base64url encoding for JWT payload.",
    )
  }

  @Test
  fun `parseJwt throws IllegalStateException if argument is not a valid JWT`() {
    assertThrows(IllegalStateException::class.java) {
      VerifiableCredential.parseJwt("hi")
    }
  }

  @Test
  fun `parseJwt throws if vc property is missing in JWT`() {
    val signerDid = DidDht.create(InMemoryKeyManager())

    val claimsSet = JwtClaimsSet.Builder()
      .subject("alice")
      .build()

    val signedJWT = Jwt.sign(signerDid, claimsSet)

    val exception = assertThrows(IllegalArgumentException::class.java) {
      VerifiableCredential.parseJwt(signedJWT)
    }

    assertEquals("jwt payload missing vc property", exception.message)
  }

  @Test
  fun `parseJwt throws if vc property in JWT payload is not an object`() {
    val signerDid = DidDht.create(InMemoryKeyManager())

    val claimsSet = JwtClaimsSet.Builder()
      .subject("alice")
      .misc("vc", "hehe troll")
      .build()

    val signedJWT = Jwt.sign(signerDid, claimsSet)
    assertThrows(MismatchedInputException::class.java) {
      VerifiableCredential.parseJwt(signedJWT)
    }

  }

  @Test
  fun `parseJwt returns an instance of VerifiableCredential on success`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidKey.create(keyManager)
    val holderDid = DidKey.create(keyManager)

    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true)
    )

    val vcJwt = vc.sign(issuerDid)

    val parsedVc = VerifiableCredential.parseJwt(vcJwt)
    assertNotNull(parsedVc)

    assertEquals(vc.type, parsedVc.type)
    assertEquals(vc.issuer, parsedVc.issuer)
    assertEquals(vc.subject, parsedVc.subject)
  }
}

class Web5TestVectorsCredentials {

  data class CreateTestInput(
    val signerPortableDid: PortableDid?,
    val credential: Map<String, Any>?,
  )

  data class VerifyTestInput(
    val vcJwt: String,
  )

  private val mapper = jacksonObjectMapper()

  @Test
  fun create() {
    val typeRef = object : TypeReference<TestVectors<CreateTestInput, Map<String, Any>?>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/credentials/create.json"), typeRef)

    testVectors.vectors.filter { it.errors == false }.forEach { vector ->
      var issuanceDate = Date()
      vector.input.credential?.get("issuanceDate")?.let {
        issuanceDate = Date.from(Instant.parse(it as String))
      }

      var expirationDate: Date? = null
      vector.input.credential?.get("expirationDate")?.let {
        expirationDate = Date.from(Instant.parse(it as String))
      }

      var credentialStatus: CredentialStatus? = null
      (vector.input.credential?.get("credentialStatus") as? Map<String, Any>)?.let {
        credentialStatus = CredentialStatus.fromMap(it)
      }

      val evidence = vector.input.credential?.get("evidence") as? List<Any>

      val vc = VerifiableCredential.create(
        type = vector.input.credential?.get("type") as String,
        issuer = vector.input.credential?.get("issuer") as String,
        subject = vector.input.credential?.get("subject") as String,
        data = vector.input.credential?.get("credentialSubject"),

        // Applying the optional fields
        credentialStatus = credentialStatus,
        issuanceDate = issuanceDate,
        expirationDate = expirationDate,
        evidence = evidence
      )

      assertNotNull(vc.vcDataModel.id)
      assertNotNull(vc.vcDataModel.issuanceDate)

      assertEquals(vector.output?.get("@context"), vc.vcDataModel.contexts.map { it.toString() })
      assertEquals(vector.output?.get("type"), vc.vcDataModel.types)
      assertEquals(vector.output?.get("issuer"), vc.vcDataModel.issuer.toString())
      assertEquals(vector.output?.get("credentialSubject"), vc.vcDataModel.credentialSubject.toMap())

      vector.output?.get("issuanceDate")?.let { expectedIssuanceDate ->
        assertEquals(expectedIssuanceDate, vc.vcDataModel.issuanceDate.toInstant()
          .atZone(ZoneId.of("UTC")).format(DateTimeFormatter.ISO_INSTANT))
      }

      vector.output?.get("expirationDate")?.let { expectedExpirationDate ->
        assertEquals(expectedExpirationDate, vc.vcDataModel.expirationDate.toInstant()
          .atZone(ZoneId.of("UTC")).format(DateTimeFormatter.ISO_INSTANT))
      }

      vector.output?.get("credentialStatus")?.let { expectedCredentialStatus ->
        assertEquals(expectedCredentialStatus, vc.vcDataModel.credentialStatus)
      }

      vector.output?.get("evidence")?.let { expectedEvidence ->
        assertEquals(expectedEvidence as List<Any>, vc.evidence)
      }
    }
  }

  @Test
  fun verify() {
    val typeRef = object : TypeReference<TestVectors<VerifyTestInput, Unit>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/credentials/verify.json"), typeRef)

    testVectors.vectors.filterNot { it.errors ?: false }.forEach { vector ->
      assertDoesNotThrow {
        VerifiableCredential.verify(vector.input.vcJwt)
      }
    }

    testVectors.vectors.filter { it.errors ?: false }.forEach { vector ->
      assertFails {
        VerifiableCredential.verify(vector.input.vcJwt)
      }
    }
  }

  @Test
  fun verifyVcJwt() {
    val typeRef = object : TypeReference<TestVectors<String, Unit>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/vc_jwt/verify.json"), typeRef)

    testVectors.vectors.filter { it.errors == false }.forEach { vector ->
      assertDoesNotThrow {
        VerifiableCredential.verify(vector.input)
      }
    }

    testVectors.vectors.filter { it.errors == true }.forEach { vector ->
      assertFails {
        VerifiableCredential.verify(vector.input)
      }
    }
  }
}
