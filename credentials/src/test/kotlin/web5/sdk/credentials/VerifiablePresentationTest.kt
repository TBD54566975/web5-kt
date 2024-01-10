package web5.sdk.credentials

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.credentials.model.InputDescriptorMapping
import web5.sdk.credentials.model.PresentationSubmission
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.key.DidKey
import java.security.SignatureException
import java.text.ParseException
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class VerifiablePresentationTest {

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
  fun `simple sign works`() {
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
  fun `presentationSubmission sign works`() {
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
    val vcJwts: Iterable<String> = listOf("vcjwt1")

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

    val header = JWSHeader.Builder(JWSAlgorithm.ES256K)
      .keyID(holderDid.uri)
      .build()

    val vpJwt = "${header.toBase64URL()}..fakeSig"

    val exception = assertThrows(SignatureException::class.java) {
      VerifiablePresentation.verify(vpJwt)
    }

    assertEquals(
      "Signature verification failed: Expected kid in JWS header to dereference a DID Document " +
        "Verification Method with an Assertion verification relationship", exception.message
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
  fun `parseJwt throws ParseException if argument is not a valid JWT`() {
    assertThrows(ParseException::class.java) {
      VerifiablePresentation.parseJwt("hi")
    }
  }
}