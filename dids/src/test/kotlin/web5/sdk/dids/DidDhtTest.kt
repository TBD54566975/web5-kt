package web5.sdk.dids

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.Service
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager
import java.net.URI
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DidDhtTest {

  @Nested
  inner class CreateTest {

    @Test
    fun `create with no options`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)

      assertNotNull(did)
      assertNotNull(did.didDocument)
      assertEquals(1, did.didDocument!!.verificationMethods.size)
      assertContains(did.didDocument!!.verificationMethods[0].id.toString(), "#0")
      assertEquals(1, did.didDocument!!.assertionMethodVerificationMethods.size)
      assertEquals(1, did.didDocument!!.authenticationVerificationMethods.size)
      assertEquals(1, did.didDocument!!.capabilityDelegationVerificationMethods.size)
      assertEquals(1, did.didDocument!!.capabilityInvocationVerificationMethods.size)
      assertNull(did.didDocument!!.keyAgreementVerificationMethods)
      assertNull(did.didDocument!!.services)
    }

    @Test
    fun `create with another key and service`() {
      val manager = InMemoryKeyManager()

      val otherKey = manager.generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1)
      val publicKeyJwk = manager.getPublicKey(otherKey).toPublicJWK()
      val verificationMethodsToAdd: Iterable<Pair<JWK, Array<PublicKeyPurpose>>> = listOf(
        Pair(publicKeyJwk, arrayOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.ASSERTION_METHOD))
      )

      val serviceToAdd = Service.builder()
        .id(URI("test-service"))
        .type("HubService")
        .serviceEndpoint("https://example.com/service)")
        .build()

      val opts: CreateDidDhtOptions = CreateDidDhtOptions(
        verificationMethodsToAdd = verificationMethodsToAdd,
        servicesToAdd = listOf(serviceToAdd)
      )
      val did = DidDht.create(manager, opts)

      assertNotNull(did)
      assertNotNull(did.didDocument)
      assertEquals(2, did.didDocument!!.verificationMethods.size)
      assertEquals(2, did.didDocument!!.assertionMethodVerificationMethods.size)
      assertEquals(2, did.didDocument!!.authenticationVerificationMethods.size)
      assertEquals(1, did.didDocument!!.capabilityDelegationVerificationMethods.size)
      assertEquals(1, did.didDocument!!.capabilityInvocationVerificationMethods.size)
      assertNull(did.didDocument!!.keyAgreementVerificationMethods)
      assertNotNull(did.didDocument!!.services)
      assertEquals(1, did.didDocument!!.services.size)
      assertContains(did.didDocument!!.services[0].id.toString(), "test-service")
    }
  }

  @Nested
  inner class PacketTest {

    @Test
    fun `to and from DNS packet - simple DID`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)

      require(did.didDocument != null)

      val packet = DidDht.toDnsPacket(did.didDocument!!)
      println(packet.toString())
    }

    @Test
    fun `to and from DNS packet - complex DID`() {
      val manager = InMemoryKeyManager()

      val otherKey = manager.generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1)
      val publicKeyJwk = manager.getPublicKey(otherKey).toPublicJWK()
      val verificationMethodsToAdd: Iterable<Pair<JWK, Array<PublicKeyPurpose>>> = listOf(
        Pair(publicKeyJwk, arrayOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.ASSERTION_METHOD))
      )

      val serviceToAdd = Service.builder()
        .id(URI("test-service"))
        .type("HubService")
        .serviceEndpoint("https://example.com/service)")
        .build()

      val opts: CreateDidDhtOptions = CreateDidDhtOptions(
        verificationMethodsToAdd = verificationMethodsToAdd,
        servicesToAdd = listOf(serviceToAdd)
      )
      val did = DidDht.create(manager, opts)

      require(did.didDocument != null)

      val packet = DidDht.toDnsPacket(did.didDocument!!)
      println(packet.toString())
    }
  }
}