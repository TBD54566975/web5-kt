package web5.sdk.dids

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager

class DidKeyTest {
  @Nested
  inner class CreateTest {
    @Test
    fun `it works`() {
      val did = DidKeyMethod.create(InMemoryKeyManager())
    }
  }

  @Nested
  inner class ResolveTest {
    @Test
    fun `it works`() {
      // did taken from test vectors here: https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/ed25519-x25519.json
      // TODO: consume all test vectors programmatically
      DidKeyMethod.resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
    }
  }
}