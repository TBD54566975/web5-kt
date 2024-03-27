package web5.sdk.credentials

import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.common.Convert
import web5.sdk.common.Json
import web5.sdk.credentials.model.ConstraintsV2
import web5.sdk.credentials.model.FieldV2
import web5.sdk.credentials.model.InputDescriptorMapping
import web5.sdk.credentials.model.InputDescriptorV2
import web5.sdk.credentials.model.PresentationDefinitionV2
import web5.sdk.credentials.model.PresentationSubmission
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.Jwa
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.methods.dht.CreateDidDhtOptions
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.jwk.DidJwk
import web5.sdk.dids.methods.key.DidKey
import web5.sdk.jose.jws.JwsHeader
import web5.sdk.jose.jwt.Jwt
import web5.sdk.jose.jwt.JwtClaimsSet
import java.security.SignatureException
import java.text.ParseException
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class VerifiablePresentationTest {

  @Suppress("LongLine")
  val validVcJwt = "eyJraWQiOiJkaWQ6a2V5OnpRM3NoZ0NqVmZucldxOUw3cjFRc3oxcmlRUldvb3pid2dKYkptTGdxRFB2OXNnNGIjelEzc" +
    "2hnQ2pWZm5yV3E5TDdyMVFzejFyaVFSV29vemJ3Z0piSm1MZ3FEUHY5c2c0YiIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJpc3Mi" +
    "OiJkaWQ6a2V5OnpRM3NoZ0NqVmZucldxOUw3cjFRc3oxcmlRUldvb3pid2dKYkptTGdxRFB2OXNnNGIiLCJzdWIiOiJkaWQ6a2V5OnpRM3No" +
    "d2Q0eVVBZldnZkdFUnFVazQ3eEc5NXFOVXNpc0Q3NzZKTHVaN3l6OW5RaWoiLCJpYXQiOjE3MDQ5MTgwODMsInZjIjp7IkBjb250ZXh0Ijpb" +
    "Imh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJTdHJlZXRD" +
    "cmVkIl0sImlkIjoidXJuOnV1aWQ6NTU2OGQyZTEtYjA0NS00MTQ3LTkxNjUtZTU3YTIxMGM2ZGVlIiwiaXNzdWVyIjoiZGlkOmtleTp6UTNz" +
    "aGdDalZmbnJXcTlMN3IxUXN6MXJpUVJXb296YndnSmJKbUxncURQdjlzZzRiIiwiaXNzdWFuY2VEYXRlIjoiMjAyNC0wMS0xMFQyMDoyMToy" +
    "M1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6elEzc2h3ZDR5VUFmV2dmR0VScVVrNDd4Rzk1cU5Vc2lzRDc3NkpMdVo3" +
    "eXo5blFpaiIsImxvY2FsUmVzcGVjdCI6ImhpZ2giLCJsZWdpdCI6dHJ1ZX19fQ.Bx0JrQERWRLpYeg3TnfrOIo4zexo3q1exPZ-Ej6j0T0YO" +
    "BVZaZ9-RqpiAM-fHKrdGUzVyXr77pOl7yGgwIO90g"

  @Test
  fun `create simple vp`() {
    val vcJwts: Iterable<String> = listOf("vcjwt1")

    val keyManager = InMemoryKeyManager()
    val holderDid = DidKey.create(keyManager)

    val vp = VerifiablePresentation.create(
      vcJwts = vcJwts,
      holder = holderDid.uri
    )

    assertNotNull(vp, "VerifiablePresentation should not be null")
    assertEquals(holderDid.uri, vp.holder, "holder should match")
    assertEquals(vcJwts, vp.verifiableCredential, "vcJwts should match")
  }

  @Test
  fun `create vp with presentation submission`() {
    val keyManager = InMemoryKeyManager()
    val holderDid = DidKey.create(keyManager)

    val vcJwts: Iterable<String> = listOf("vcjwt1", "vcjwt2")

    val presentationSubmission = PresentationSubmission(
      id = "presentationSubmissionId",
      definitionId = "definitionId",
      descriptorMap = listOf(
        InputDescriptorMapping(
          id = "descriptorId",
          format = "format",
          path = "path"
        )
      )
    )

    val vp = VerifiablePresentation.create(
      vcJwts = vcJwts,
      holder = holderDid.uri,
      additionalData = mapOf("presentation_submission" to presentationSubmission)
    )

    val vpDataModelMap = vp.vpDataModel.toMap()
    val mappedPresentationSubmission = vpDataModelMap["presentation_submission"] as? PresentationSubmission

    assertNotNull(mappedPresentationSubmission, "Mapped PresentationSubmission should not be null")
    assertEquals(presentationSubmission, mappedPresentationSubmission, "PresentationSubmission should match")
  }


  @Test
  fun `creates simple signed vp`() {
    val keyManager = InMemoryKeyManager()
    val holderDid = DidKey.create(keyManager)

    val vp = VerifiablePresentation.create(
      vcJwts = listOf("vcjwt1", "vcjwt2"),
      holder = holderDid.uri
    )

    val vpJwt = vp.sign(holderDid)
    assertNotNull(vpJwt)
  }

  @Test
  fun `creates signed vp with presentationSubmission`() {
    val keyManager = InMemoryKeyManager()
    val holderDid = DidKey.create(keyManager)

    val vcJwts: Iterable<String> = listOf("vcjwt1", "vcjwt2")

    val presentationSubmission = PresentationSubmission(
      id = "presentationSubmissionId",
      definitionId = "definitionId",
      descriptorMap = listOf(
        InputDescriptorMapping(
          id = "descriptorId",
          format = "format",
          path = "path"
        )
      )
    )

    val vp = VerifiablePresentation.create(
      vcJwts = vcJwts,
      holder = holderDid.uri,
      type = "PresentationSubmission",
      additionalData = mapOf("presentation_submission" to presentationSubmission)
    )

    val vpJwt = vp.sign(holderDid)

    assertNotNull(vpJwt)
    assertEquals(vcJwts, vp.verifiableCredential)
    assertEquals(presentationSubmission, vp.vpDataModel.toMap()["presentation_submission"] as? PresentationSubmission)
  }

  @Test
  fun `verify does not throw an exception if vp is valid`() {
    val vcJwts: Iterable<String> = listOf(validVcJwt)

    val keyManager = InMemoryKeyManager()
    val holderDid = DidKey.create(keyManager)

    val vp = VerifiablePresentation.create(
      vcJwts = vcJwts,
      holder = holderDid.uri
    )

    val vpJwt = vp.sign(holderDid)

    assertDoesNotThrow { VerifiablePresentation.verify(vpJwt) }
  }

  @Test
  fun `verify throws on invalid jwt`() {
    val keyManager = InMemoryKeyManager()
    val holderDid = DidKey.create(keyManager)

    val header = JwsHeader.Builder()
      .type("JWT")
      .algorithm(Jwa.ES256K.name)
      // todo does fragment always start with a # ? if not need to add # in the middle
      .keyId("${holderDid.uri}${holderDid.did.fragment}")
      .build()

    val vpJwt = "${Convert(Json.stringify(header)).toBase64Url()}..fakeSig"

    val exception = assertThrows(SignatureException::class.java) {
      VerifiablePresentation.verify(vpJwt)
    }

    assertContains(
      exception.message!!, "Malformed JWT. Invalid base64url encoding for JWT payload.",
    )
  }

  @Test
  fun `parseJwt returns an instance of VerifiablePresentation on success`() {
    val keyManager = InMemoryKeyManager()
    val holderDid = DidKey.create(keyManager)

    val vcJwts: Iterable<String> = listOf("vcjwt1", "vcjwt2")

    val vp = VerifiablePresentation.create(
      vcJwts = vcJwts,
      holder = holderDid.uri
    )

    val vpJwt = vp.sign(holderDid)

    val parsedVp = VerifiablePresentation.parseJwt(vpJwt)
    assertNotNull(parsedVp)

    assertEquals(vp.holder, parsedVp.holder)
    assertEquals(vp.verifiableCredential, parsedVp.verifiableCredential)
  }

  @Test
  fun `parseJwt throws IllegalStateException if argument is not a valid JWT`() {
    assertThrows(IllegalStateException::class.java) {
      VerifiablePresentation.parseJwt("hi")
    }
  }

  @Test
  fun `parseJwt throws if vp property is missing in JWT`() {
    val signerDid = DidDht.create(InMemoryKeyManager())

    val claimsSet = JwtClaimsSet.Builder()
      .subject("alice")
      .build()

    val signedJWT = Jwt.sign(signerDid, claimsSet)

    val exception = assertThrows(IllegalArgumentException::class.java) {
      VerifiablePresentation.parseJwt(signedJWT)
    }

    assertEquals("jwt payload missing vp property", exception.message)
  }

  @Test
  fun `verify throws exception for DIDs without an assertionMethod`() {
    val keyManager = InMemoryKeyManager()

    //Create a DHT DID without an assertionMethod
    val alias = keyManager.generatePrivateKey(AlgorithmId.secp256k1)
    val verificationJwk = keyManager.getPublicKey(alias)
    val verificationMethodsToAdd = listOf(
      Triple(
        verificationJwk,
        emptyList<Purpose>(),
        "did:web:tbd.website"
      )
    )
    val issuerDid = DidDht.create(
      InMemoryKeyManager(),
      CreateDidDhtOptions(verificationMethods = verificationMethodsToAdd)
    )

    val header = JwsHeader.Builder()
      .type("JWT")
      .algorithm(Jwa.ES256K.name)
      .keyId(issuerDid.uri)
      .build()
    //A detached payload JWT
    val vpJwt = "${Convert(Json.stringify(header)).toBase64Url()}..fakeSig"

    val exception = assertThrows(SignatureException::class.java) {
      VerifiablePresentation.verify(vpJwt)
    }
    assertContains(
      exception.message!!, "Malformed JWT. Invalid base64url encoding for JWT payload.",
    )
  }

  data class EmploymentStatus(val employmentStatus: String)
  data class PIICredential(val name: String, val dateOfBirth: String)

  @Test
  fun `full flow with did dht`() {
    val keyManager = InMemoryKeyManager()
    val issuerDid = DidDht.create(keyManager)
    val holderDid = DidDht.create(keyManager)

    val vc = VerifiableCredential.create(
      type = "EmploymentCredential",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = EmploymentStatus(employmentStatus = "employed")
    )

    val vc2 = VerifiableCredential.create(
      type = "PIICredential",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = PIICredential(name = "Alice Smith", dateOfBirth = "2001-12-21T17:02:01Z")
    )

    val vcJwt1 = vc.sign(issuerDid)
    val vcJwt2 = vc2.sign(issuerDid)

    val presentationDefinition = PresentationDefinitionV2(
      id = "presDefIdloanAppVerification123",
      name = "Loan Application Employment Verification",
      purpose = "To verify applicant’s employment, date of birth, and name",
      inputDescriptors = listOf(
        InputDescriptorV2(
          id = "employmentVerification",
          purpose = "Confirm current employment status",
          constraints = ConstraintsV2(
            fields = listOf(FieldV2(path = listOf("$.vc.credentialSubject.employmentStatus")))
          )
        ),
        InputDescriptorV2(
          id = "dobVerification",
          purpose = "Confirm the applicant’s date of birth",
          constraints = ConstraintsV2(
            fields = listOf(FieldV2(path = listOf("$.vc.credentialSubject.dateOfBirth")))
          )
        ),
        InputDescriptorV2(
          id = "nameVerification",
          purpose = "Confirm the applicant’s legal name",
          constraints = ConstraintsV2(
            fields = listOf(FieldV2(path = listOf("$.vc.credentialSubject.name")))
          )
        )
      )
    )

    val presentationResult = PresentationExchange.createPresentationFromCredentials(
      vcJwts= listOf(vcJwt1, vcJwt2),
      presentationDefinition= presentationDefinition
    )

    val verifiablePresentation = VerifiablePresentation.create(
      vcJwts = listOf(vcJwt1, vcJwt2),
      holder = holderDid.uri,
      additionalData = mapOf("presentation_submission" to presentationResult)
    )

    val vpJwt = verifiablePresentation.sign(holderDid)

    assertDoesNotThrow {
      VerifiablePresentation.verify(vpJwt)
    }
  }
}