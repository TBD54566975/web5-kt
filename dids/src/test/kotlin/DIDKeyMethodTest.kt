import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import web5.dids.CreateDIDKeyOptions
import web5.dids.DIDKeyMethod
import kotlin.test.assertContains

class DIDKeyMethodTest {

  @Test
  fun authorizeReturnsTrue() {
    val privateJWK = OctetKeyPairGenerator(Curve.Ed25519).generate()
    val creatorOp = DIDKeyMethod.creator(CreateDIDKeyOptions(privateJWK.toPublicJWK()))
    assertTrue(
      DIDKeyMethod.authorize(creatorOp)
    )
  }

  @Test
  fun createContainsCorrectPrefix() {
    val privateJWK = OctetKeyPairGenerator(Curve.Ed25519).generate()
    assertContains(
      DIDKeyMethod.creator(CreateDIDKeyOptions(privateJWK.toPublicJWK())).create().did.toString(),
      "did:key:z6Mk"
    )
  }
}