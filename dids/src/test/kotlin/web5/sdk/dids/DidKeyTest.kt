package web5.sdk.dids

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager

// TODO: use all relevant test vectors from https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/
class DidKeyTest {
  @Nested
  inner class CreateTest {
    @Test
    fun `it works`() {
      val did = DidKey.create(InMemoryKeyManager())
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