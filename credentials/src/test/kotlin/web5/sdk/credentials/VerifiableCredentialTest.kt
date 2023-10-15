package web5.sdk.credentials

import com.nimbusds.jose.JOSEObjectType
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
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.DidKey
import java.text.ParseException
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

data class StreetCredibility(val localRespect: String, val legit: Boolean)
class VerifiableCredentialTest {
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
  fun `signing works`() {
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
    val parsedJwt = SignedJWT.parse(vcJwt) // validates JWT

    val didDocument = issuerDid.resolve().didDocument
    val assertionMethod = didDocument.assertionMethodVerificationMethodsDereferenced.first()

    val jwtHeader = parsedJwt.header
    assertNotNull(jwtHeader.algorithm)
    assertEquals(JOSEObjectType.JWT, jwtHeader.type)
    assertEquals(assertionMethod.id.toString(), jwtHeader.keyID)

    val jwtClaims = parsedJwt.jwtClaimsSet
    assertNotNull(jwtClaims.issueTime)
    assertNotNull(jwtClaims.getClaim("vc"))
    assertEquals(issuerDid.uri, jwtClaims.issuer)
    assertEquals(holderDid.uri, jwtClaims.subject)

    val vcDataModelJson = jwtClaims.getJSONObjectClaim("vc")
    val vcDataModel = VcDataModel.fromMap(vcDataModelJson)

    assertEquals(holderDid.uri, vcDataModel.credentialSubject.id.toString())
    assertContains(vcDataModel.types, "StreetCred")
  }

  @Test
  fun `verify does not throw an exception if vc is legit`() {
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
    VerifiableCredential.verify(vcJwt)
  }

  @Test
  fun `parseJwt throws ParseException if argument is not a valid JWT`() {
    assertThrows(ParseException::class.java) {
      VerifiableCredential.parseJwt("hi")
    }
  }

  @Test
  fun `parseJwt throws if vc property is missing in JWT`() {
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
      VerifiableCredential.parseJwt(randomJwt)
    }

    assertEquals("jwt payload missing vc property", exception.message)
  }

  @Test
  fun `parseJwt throws if vc property in JWT payload is not an object`() {
    val jwk = OctetKeyPairGenerator(Curve.Ed25519).generate()
    val signer: JWSSigner = Ed25519Signer(jwk)

    val claimsSet = JWTClaimsSet.Builder()
      .subject("alice")
      .claim("vc", "hehe troll")
      .build()

    val signedJWT = SignedJWT(
      JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.keyID).build(),
      claimsSet
    )

    signedJWT.sign(signer)
    val randomJwt = signedJWT.serialize()

    val exception = assertThrows(IllegalArgumentException::class.java) {
      VerifiableCredential.parseJwt(randomJwt)
    }

    assertEquals("expected vc property in JWT payload to be an object", exception.message)
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