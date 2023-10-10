package web5.sdk.dids

import com.nimbusds.jose.jwk.JWK
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager

// TODO: use all relevant test vectors from https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/
class DidKeyTest {
  @Nested
  inner class CreateTest {
    @Test
    fun `it works`() {
      val manager = InMemoryKeyManager()
      val did = DidKey.create(manager)

      val keyAliaz = run {
        val didResolutionResult = DidResolvers.resolve(did.uri)
        val verificationMethod = didResolutionResult.didDocument.allVerificationMethods[0]

        require(verificationMethod != null) { "no verification method found" }

        val jwk = JWK.parse(verificationMethod.publicKeyJwk)
        jwk.keyID
      }
      val publicKey = did.keyManager.getPublicKey(keyAliaz)
    }
  }

  @Nested
  inner class ResolveTest {
    @Test
    fun `it works`() {
      DidKey.resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
    }
  }
}