package web5.sdk.dids

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.dht.DidDht
import kotlin.test.assertEquals

class DidResolversTest {

  // TODO: use all relevant test vectors from https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/
  @Test
  fun `it works`() {
    DidResolvers.resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
  }

  @Test
  fun `resolving a default dht did contains assertion method`() {
    val dhtDid = DidDht.create(InMemoryKeyManager(), null)

    val resolutionResult = DidResolvers.resolve(dhtDid.uri)
    assertNotNull(resolutionResult.didDocument!!.assertionMethod)
  }

  @Test
  fun `resolving an invalid did throws an exception`() {
    val exception = assertThrows<IllegalArgumentException> {
      DidResolvers.resolve("did:invalid:123")
    }
    assertEquals("Resolving did:invalid not supported", exception.message)
  }

  @Test
  fun `addResolver adds a custom resolver`() {
    val resolver: DidResolver = { _ -> DidResolutionResult(null, null) }
    DidResolvers.addResolver("test", resolver)
    assertNotNull(DidResolvers.resolve("did:test:123"))
  }
}
