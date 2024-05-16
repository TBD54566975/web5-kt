package web5.sdk.dids.did

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.spy
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.didcore.Service
import web5.sdk.dids.methods.jwk.DidJwk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class BearerDidTest {

  @Test
  fun `addService should add a new service to the DID Document`() {
    val bearerDid = DidJwk.create(InMemoryKeyManager())

    val newService = Service(id = "service3", type = "ServiceType3", serviceEndpoint = listOf("https://endpoint3"))
    val updatedBearerDid = bearerDid.addService(newService)

    assertEquals(1, updatedBearerDid.document.service?.size)
    assertTrue(updatedBearerDid.document.service?.any { it.id == "service3" } == true)
  }

  @Test
  fun `deleteService should remove a service from the DID Document`() {
    val bearerDid = DidJwk.create(InMemoryKeyManager())

    val serviceToDelete = Service(id = "service1", type = "ServiceType1", serviceEndpoint = listOf("https://endpoint1"))
    val bearerDidWithService = bearerDid.addService(serviceToDelete)

    val updatedBearerDid = bearerDidWithService.deleteService("service1")

    assertTrue(updatedBearerDid.document.service.isNullOrEmpty())
  }

  @Test
  fun `clearServices should remove all services from the DID Document`() {
    val bearerDid = DidJwk.create(InMemoryKeyManager())

    val service1 = Service(id = "service1", type = "ServiceType1", serviceEndpoint = listOf("https://endpoint1"))
    val service2 = Service(id = "service2", type = "ServiceType2", serviceEndpoint = listOf("https://endpoint2"))
    val bearerDidWithServices = bearerDid.addService(service1).addService(service2)

    val updatedBearerDid = bearerDidWithServices.clearServices()

    assertTrue(updatedBearerDid.document.service.isNullOrEmpty())
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