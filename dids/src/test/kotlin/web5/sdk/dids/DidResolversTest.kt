package web5.sdk.dids

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.dht.DidDht

class DidResolversTest {

  // TODO: use all relevant test vectors from https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/
  @Test
  fun `it works`() {
    DidResolvers.resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", null)
  }

  @Test
  fun `resolving a default ion did contains assertion method`() {
    val ionDid = DidDht.create(InMemoryKeyManager())

    val resolutionResult = DidResolvers.resolve(ionDid.uri)
    assertNotNull(resolutionResult.didDocument!!.assertionMethodVerificationMethodsDereferenced)
  }
}