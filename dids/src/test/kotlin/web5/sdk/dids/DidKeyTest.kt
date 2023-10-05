package web5.sdk.dids

import com.nimbusds.jose.jwk.JWK
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager
import kotlin.test.assertEquals

class DidKeyTest {
  @Nested
  inner class CreateTest {
    @Test
    fun `creating a did key and resolving matches the key manager`() = runTest {
      val keyManager = InMemoryKeyManager()
      val (did, metadata) = DidKeyMethod.create(keyManager)

      val storedJwk = keyManager.getPublicKey(metadata.keyAlias)
      val results = DidKeyMethod.resolve(did.uri)
      assertEquals(
        storedJwk,
        JWK.parse(results.didDocument.verificationMethods[0].publicKeyJwk)
      )
    }
  }

  @Nested
  inner class ResolveTest {
    @Test
    fun `it works`() = runTest {
      // did taken from test vectors here: https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/ed25519-x25519.json
      // TODO: consume all test vectors programmatically
      DidKeyMethod.resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
    }
  }
}