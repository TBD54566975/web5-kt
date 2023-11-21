package web5.sdk.dids.methods.dht

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.Service
import foundation.identity.did.parser.ParserException
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.util.hex
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.common.ZBase32
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.PublicKeyPurpose
import java.net.URI
import kotlin.test.assertContains
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

      assertDoesNotThrow {
        DidDht.validate(identifier)
      }
    }

    @Test
    fun `validate identity key`() {
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
      val publicKey = manager.getPublicKey(keyAlias)
      val identifier = DidDht.getDidIdentifier(publicKey)

      assertDoesNotThrow {
        DidDht.validateIdentityKey(identifier, manager)
      }
    }

    @Test
    fun `validate identity key throws exception when private key not in manager`() {
      val manager = InMemoryKeyManager()

      val exception = assertThrows<IllegalArgumentException> {
        DidDht.validateIdentityKey("did:dht:1bxdi3tbf1ud6cpk3ef9pz83erk9c6mmh877qfhfcd7ppzbgh7co", manager)
      }
      assertEquals("key with alias azV60laS2T5XWKymWbZO8f-tz_LFy87aIl07pI01P9w not found", exception.message)
    }

    @Test
    fun `validate identity key throws exception when encoded bytes are not 32`() {
      val manager = InMemoryKeyManager()

      val exception = assertThrows<IllegalArgumentException> {
        DidDht.validateIdentityKey("did:dht:1bxdi3tbf1ud6cpk3ef9pz83erk9c6mmh877qfhfcd7ppzbgh7co7", manager)
      }
      assertEquals(
        "expected size of decoded identifier \"1bxdi3tbf1ud6cpk3ef9pz83erk9c6mmh877qfhfcd7ppzbgh7co7\" to be 32",
        exception.message
      )
    }
  }

  @Nested
  inner class DidDhtTest {

    @Test
    fun `create with no options`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager, CreateDidDhtOptions(publish = false))

      assertDoesNotThrow { did.validate() }
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

      val serviceToAdd =
        Service.builder()
          .id(URI("test-service"))
          .type("HubService")
          .serviceEndpoint("https://example.com/service)")
          .build()

      val opts = CreateDidDhtOptions(
        verificationMethods = verificationMethodsToAdd, services = listOf(serviceToAdd), publish = false
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

    @Test
    fun `create and transform to packet with types`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager, CreateDidDhtOptions(publish = false))

      assertDoesNotThrow { did.validate() }
      assertNotNull(did)
      assertNotNull(did.didDocument)

      val indexes = listOf(DidDhtTypeIndexing.Corporation, DidDhtTypeIndexing.SoftwarePackage)
      val packet = did.toDnsPacket(did.didDocument!!, indexes)
      assertNotNull(packet)

      val docTypesPair = did.fromDnsPacket(msg = packet)
      assertNotNull(docTypesPair)
      assertNotNull(docTypesPair.first)
      assertNotNull(docTypesPair.second)
      assertEquals(did.didDocument, docTypesPair.first)
      assertEquals(indexes, docTypesPair.second)
    }

    @Test
    fun `create with publishing`() {
      val manager = InMemoryKeyManager()
      val api = DidDhtApi { engine = mockEngine() }
      val did = api.create(manager, CreateDidDhtOptions(publish = true))

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
    fun `resolves a did dht value`() {
      val api = DidDhtApi { engine = mockEngine() }
      // known DID associated with our mock response, needed to verify the payload's signature
      val knownDid = "did:dht:8b1oyfjr56zab9ajjgpomsaxgtncrty6hpbnq5htft13ysix66wo"

      assertDoesNotThrow {
        val result = api.resolve(knownDid)
        assertNotNull(result)
        assertNotNull(result.didDocument)
        assertEquals(knownDid, result.didDocument.id.toString())
      }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun mockEngine() = MockEngine { request ->
      val hexResponse = "38e8fb912b5196680fe6c6d7eb555d6e8a68252185b1d2d4619f003ab96cf52cb67cbaf17292d070" +
        "66c05dd36d383c254317e0af3fd03b87bc9048d3f4179a0c000000006554012f000004000000000200000000035f6b30" +
        "045f646964000010000100001c2000373669643d303b743d303b6b3d4f475541465354667234445f43556d62426473504e4" +
        "554435242376a516964766b53786c6b46717639366bc0100010000100001c20002322766d3d6b303b617574683d6b" +
        "303b61736d3d6b303b696e763d6b303b64656c3d6b30"
      when {
        request.url.encodedPath == "/" && request.method == HttpMethod.Put -> {
          respond("Success", HttpStatusCode.OK)
        }

        request.url.encodedPath.matches("/\\w+".toRegex()) && request.method == HttpMethod.Get -> {
          respond(hexResponse.hexToByteArray(), HttpStatusCode.OK)
        }

        else -> respond("Success", HttpStatusCode.OK)
      }
    }
  }

  @Nested
  inner class DnsPacketTest {
    @Test
    fun `to and from DNS packet - simple DID`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager, CreateDidDhtOptions(publish = false))

      require(did.didDocument != null)

      val packet = DidDht.toDnsPacket(did.didDocument!!)
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDnsPacket(did.didDocument!!.id.toString(), packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)

      assertEquals(did.didDocument.toString(), didFromPacket.first.toString())
    }

    @Test
    fun `to and from DNS packet - DID with types`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager, CreateDidDhtOptions(publish = false))

      require(did.didDocument != null)

      val indexes = listOf(DidDhtTypeIndexing.Corporation, DidDhtTypeIndexing.SoftwarePackage)
      val packet = DidDht.toDnsPacket(did.didDocument!!, indexes)
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDnsPacket(did.didDocument!!.id.toString(), packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)
      assertNotNull(didFromPacket.second)

      assertEquals(did.didDocument.toString(), didFromPacket.first.toString())
      assertEquals(indexes, didFromPacket.second)
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

      val opts = CreateDidDhtOptions(
        verificationMethods = verificationMethodsToAdd, services = listOf(serviceToAdd), publish = false
      )
      val did = DidDht.create(manager, opts)

      require(did.didDocument != null)

      val packet = DidDht.toDnsPacket(did.didDocument!!)
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDnsPacket(did.didDocument!!.id.toString(), packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)

      assertEquals(did.didDocument.toString(), didFromPacket.first.toString())
    }
  }

  @Nested
  inner class ValidateTest {
    @Test
    fun `throws exception if parsing Did fails`() {
      assertThrows<ParserException> { DidDht.validate("abcd") }
    }

    @Test
    fun `throws exception if did method isnt dht`() {
      assertThrows<IllegalArgumentException> { DidDht.validate("did:key:abcd123") }
    }

    @Test
    fun `throws exception if identifier cannot be zbase32 decoded`() {
      assertThrows<java.lang.IllegalArgumentException> { DidDht.validate("did:dht:abcd123") }
    }

    @Test
    fun `throws exception if decoded identifier is larger than 32 bytes`() {
      val kakaId = ZBase32.encode("Hakuna matata Hakuna Matata Hakuna Matata".toByteArray())
      assertThrows<java.lang.IllegalArgumentException> { DidDht.validate("did:dht:$kakaId") }
    }

    @Test
    fun `throws exception if decoded identifier is smaller than 32 bytes`() {
      val kakaId = ZBase32.encode("a".toByteArray())
      assertThrows<java.lang.IllegalArgumentException> { DidDht.validate("did:dht:$kakaId") }
    }
  }
}