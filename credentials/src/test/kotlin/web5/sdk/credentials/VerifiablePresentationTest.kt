package web5.sdk.credentials

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.credentials.model.InputDescriptorMapping
import web5.sdk.credentials.model.PresentationSubmission
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.methods.dht.CreateDidDhtOptions
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.key.DidKey
import java.security.SignatureException
import java.text.ParseException
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
      holder = holderDid.did.uri
    )

    assertNotNull(vp, "VerifiablePresentation should not be null")
    assertEquals(holderDid.did.uri, vp.holder, "holder should match")
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
      holder = holderDid.did.uri,
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
      holder = holderDid.did.uri
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
      holder = holderDid.did.uri,
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
      holder = holderDid.did.uri
    )

    val vpJwt = vp.sign(holderDid)

    assertDoesNotThrow { VerifiablePresentation.verify(vpJwt) }
  }

  @Test
  fun `verify throws on invalid jwt`() {
    val keyManager = InMemoryKeyManager()
    val holderDid = DidKey.create(keyManager)

    val header = JWSHeader.Builder(JWSAlgorithm.ES256K)
      .keyID(holderDid.did.uri)
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
      holder = holderDid.did.uri
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

  @Test
  fun `parseJwt throws if vp property is missing in JWT`() {
    val jwk = OctetKeyPairGenerator(Curve.Ed25519).generate()
    val signer: JWSSigner = Ed25519Signer(jwk)

    val claimsSet = JWTClaimsSet.Builder()
      .subject("alice")
      .build()

    val signedJWT = SignedJWT(
      JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.keyID).build(),
      claimsSet
    )

    signedJWT.sign(signer)
    val randomJwt = signedJWT.serialize()
    val exception = assertThrows(IllegalArgumentException::class.java) {
      VerifiablePresentation.parseJwt(randomJwt)
    }

    assertEquals("jwt payload missing vp property", exception.message)
  }

  @Test
  fun `verify throws exception for DIDs without an assertionMethod`() {
    val keyManager = InMemoryKeyManager()

    //Create a DHT DID without an assertionMethod
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

    val header = JWSHeader.Builder(JWSAlgorithm.ES256K)
      .keyID(issuerDid.did.uri)
      .build()
    //A detached payload JWT
    val vpJwt = "${header.toBase64URL()}..fakeSig"

    val exception = assertThrows(SignatureException::class.java) {
      VerifiablePresentation.verify(vpJwt)
    }
    assertEquals(
      "Signature verification failed: Expected kid in JWS header to dereference a DID Document " +
        "Verification Method with an Assertion verification relationship", exception.message
    )
  }
}