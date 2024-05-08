package web5.sdk.dids.did

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.spy
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.didcore.DidDocument
import web5.sdk.dids.didcore.Service
import web5.sdk.dids.methods.dht.CreateDidDhtOptions
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.jwk.DidJwk
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class BearerDidTest {

  @Test
  fun `append service endpoint to existing did`() {
    val keyManager = InMemoryKeyManager()
    var myBearerDid = DidDht.create(keyManager, CreateDidDhtOptions(publish = true))

    val existingBearerDid: BearerDid = myBearerDid

    val serviceToAdd = Service.Builder()
      .id("pfi")
      .type("PFI")
      .serviceEndpoint(listOf("https://example.com/"))
      .build()

    val newServiceList = existingBearerDid.document.service.orEmpty() + serviceToAdd
    val updatedBearerDid = DidDht.update(existingBearerDid,
                                         CreateDidDhtOptions(services = newServiceList))

    DidDht.publish(updatedBearerDid.keyManager, updatedBearerDid.document)
    assert(updatedBearerDid.document.service!!.contains(serviceToAdd))





  }

  @Test
  fun `getSigner should return a signer and verification method`() {
    val keyManager = spy(InMemoryKeyManager())

    val did = DidJwk.create(keyManager)
    val expectedVm = did.document.verificationMethod?.first()
    val testPayload = "testPayload".toByteArray()
    val expectedSignature = "signature".toByteArray()
    doReturn(expectedSignature).whenever(keyManager).sign(any(), eq(testPayload))

    val (signer, vm) = did.getSigner()

    val signature = signer(testPayload)

    assertEquals(expectedVm, vm)
    verify(keyManager).sign(any(), eq(testPayload))
    assertArrayEquals(expectedSignature, signature)

  }

  @Test
  fun `export returns a portable did with correct attributes`() {
    val bearerDid = DidJwk.create(InMemoryKeyManager())
    val portableDid = bearerDid.export()

    assertEquals(portableDid.uri, bearerDid.uri)
    assertEquals(portableDid.document, bearerDid.document)
    assertEquals(1, portableDid.privateKeys.size)
  }

  @Test
  fun `import should return a BearerDid object`() {
    val portableDid = DidJwk.create(InMemoryKeyManager()).export()
    val bearerDid = DidJwk.import(portableDid)

    assertEquals(portableDid.uri, bearerDid.uri)
    assertEquals(portableDid.document, bearerDid.document)
    val portableDidKid = portableDid.privateKeys[0].kid ?: portableDid.privateKeys[0].computeThumbprint()
    assertNotNull(bearerDid.keyManager.getPublicKey(portableDidKid))
    val bearerDidKid = bearerDid.document.verificationMethod?.first()?.publicKeyJwk?.kid
      ?: bearerDid.document.verificationMethod?.first()?.publicKeyJwk?.computeThumbprint()
    assertEquals(portableDidKid, bearerDidKid)
  }

}