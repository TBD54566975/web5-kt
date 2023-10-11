package web5.sdk.credentials

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.DidKey
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
}