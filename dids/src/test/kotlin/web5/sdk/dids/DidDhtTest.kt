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
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DidDhtTest {

  @Nested
  inner class UtilsTest {
    @Test
    fun `did dht identifier`() {
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
      val publicKey = manager.getPublicKey(keyAlias)

      val identifier = DidDht.getDidIdentifier(publicKey)
      assertNotNull(identifier)

      val isValid = DidDht.isValid(identifier)
      assertEquals(true, isValid)
    }
  }

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
  inner class DnsPacketTest {

    @Test
    fun `to and from DNS packet - simple DID`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)

      require(did.didDocument != null)

      val packet = DidDht.toDnsPacket(did.didDocument!!)
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDNSPacket(did.didDocument!!.id.toString(), packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)

      assertEquals(did.didDocument.toString(), didFromPacket.first.toString())
    }

    @Test
    fun `to and from DNS packet - DID with types`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)

      require(did.didDocument != null)

      val types = listOf(1, 2)
      val packet = DidDht.toDnsPacket(did.didDocument!!, types)
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDNSPacket(did.didDocument!!.id.toString(), packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)
      assertNotNull(didFromPacket.second)

      assertEquals(did.didDocument.toString(), didFromPacket.first.toString())
      assertEquals(types, didFromPacket.second)
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
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDNSPacket(did.didDocument!!.id.toString(), packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)

      assertEquals(did.didDocument.toString(), didFromPacket.first.toString())
    }
  }
}