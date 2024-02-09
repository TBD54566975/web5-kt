package web5.sdk.dids

import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.ion.DidIon
import web5.sdk.dids.methods.web.DidWeb
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DidIntegrationTest {
  @Test
  fun `create ion did over network`() {
    val did = DidIon.create(InMemoryKeyManager())
    assertContains(did.uri, "did:ion:")
    assertTrue(did.creationMetadata!!.longFormDid.startsWith(did.uri))
  }

  @Test
  fun `create dht did over network`() {
    val did = DidDht.create(InMemoryKeyManager())
    assertContains(did.uri, "did:dht:")
  }

  @Test
  fun `resolve an existing web did`() {
    val did = DidWeb.resolve("did:web:www.linkedin.com")
    assertEquals("did:web:www.linkedin.com", did.didDocument!!.id.toString())
  }
}