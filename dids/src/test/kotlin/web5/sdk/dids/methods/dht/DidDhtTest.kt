package web5.sdk.dids.methods.dht

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import web5.sdk.common.Json
import web5.sdk.common.ZBase32
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.JwaCurve
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.PurposesDeserializer
import web5.sdk.dids.didcore.DidDocument
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.didcore.Service
import web5.sdk.dids.exceptions.InvalidIdentifierException
import web5.sdk.dids.exceptions.InvalidIdentifierSizeException
import web5.sdk.dids.exceptions.InvalidMethodNameException
import web5.sdk.dids.exceptions.ParserException
import web5.sdk.testing.TestVectors
import java.io.File
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
      val keyAlias = manager.generatePrivateKey(AlgorithmId.Ed25519)
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
      val keyAlias = manager.generatePrivateKey(AlgorithmId.Ed25519)
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
        "expected size of decoded identifier 1bxdi3tbf1ud6cpk3ef9pz83erk9c6mmh877qfhfcd7ppzbgh7co7 to be 32",
        exception.message
      )
    }
  }

  @Nested
  inner class DidDhtTest {

    @Test
    fun `create with no options`() {
      val manager = InMemoryKeyManager()
      val bearerDid = DidDht.create(manager, CreateDidDhtOptions(publish = false))

      assertDoesNotThrow { DidDht.validate(bearerDid.did.url) }
      assertNotNull(bearerDid)
      assertNotNull(bearerDid.document)
      assertEquals(1, bearerDid.document.verificationMethod?.size)
      assertContains(bearerDid.document.verificationMethod?.get(0)?.id!!, "#0")
      assertEquals(1, bearerDid.document.assertionMethod?.size)
      assertEquals(1, bearerDid.document.authentication?.size)
      assertEquals(1, bearerDid.document.capabilityDelegation?.size)
      assertEquals(1, bearerDid.document.capabilityInvocation?.size)
      assertNull(bearerDid.document.keyAgreement)
      assertNull(bearerDid.document.service)
    }

    @Test
    fun `create and transform to packet with types`() {
      val manager = InMemoryKeyManager()
      val bearerDid = DidDht.create(manager, CreateDidDhtOptions(publish = false))

      assertDoesNotThrow { DidDht.validate(bearerDid.did.url) }
      assertNotNull(bearerDid)
      assertNotNull(bearerDid.document)

      val indexes = listOf(DidDhtTypeIndexing.Corporation, DidDhtTypeIndexing.SoftwarePackage)
      val packet = DidDht.toDnsPacket(bearerDid.document, indexes)
      assertNotNull(packet)

      val docTypesPair = DidDht.fromDnsPacket(bearerDid.did.url, packet)
      assertNotNull(docTypesPair)
      assertNotNull(docTypesPair.first)
      assertNotNull(docTypesPair.second)
      assertEquals(bearerDid.document.toString(), docTypesPair.first.toString())
      assertEquals(indexes, docTypesPair.second)
    }

    @Test
    fun `create with publishing`() {
      val manager = InMemoryKeyManager()
      val api = DidDhtApi { engine = mockEngine() }
      val did = api.create(manager, CreateDidDhtOptions(publish = true))

      assertNotNull(did)
      assertNotNull(did.document)
      assertEquals(1, did.document.verificationMethod?.size)
      assertContains(did.document.verificationMethod?.get(0)?.id!!, "#0")
      assertEquals(1, did.document.assertionMethod?.size)
      assertEquals(1, did.document.authentication?.size)
      assertEquals(1, did.document.capabilityDelegation?.size)
      assertEquals(1, did.document.capabilityInvocation?.size)
      assertNull(did.document.keyAgreement)
      assertNull(did.document.service)
    }

    @Test
    fun `resolves a did dht value`() {
      val api = DidDhtApi { engine = mockEngine() }
      // known DID associated with our mock response, needed to verify the payload's signature
      val knownDid = "did:dht:qd5pz3sfsmhwhts9auy1qe6cwniemss4bpm3qxm8modtr148z17y"

      assertDoesNotThrow {
        val result = api.resolve(knownDid)
        assertNotNull(result)
        assertNotNull(result.didDocument)
        assertEquals(knownDid, result.didDocument!!.id)
      }
    }

    @Test
    fun `resolves a known did dht value`() {
      val api = DidDhtApi { }
      // known DID associated with our mock response, needed to verify the payload's signature
      val knownDid = "did:dht:ozn5c51ruo7z63u1h748ug7rw5p1mq3853ytrd5gatu9a8mm8f1o"

      assertDoesNotThrow {
        val result = api.resolve(knownDid)
        assertNotNull(result)
        assertNotNull(result.didDocument)
        assertEquals(knownDid, result.didDocument!!.id)
      }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun mockEngine() = MockEngine { request ->
      val hexResponse = "1ad37b5b8ed6c5fc87b64fe4849d81e7446c31b36138d03b9f6d68837123d6ae6aedf91e0340a7c83cd53b95a600" +
        "ffe4a2264c3c677d7d16ca6bd30e05fa820c00000000659dd40e000004000000000200000000035f6b30045f64696400001000010000" +
        "1c2000373669643d303b743d303b6b3d63506262357357792d553547333854424a79504d6f4b714632746f4c563563395a317748456b" +
        "7448764c6fc0100010000100001c20002322766d3d6b303b617574683d6b303b61736d3d6b303b696e763d6b303b64656c3d6b30"

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

      val packet = DidDht.toDnsPacket(did.document)
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDnsPacket(did.document.id, packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)

      assertEquals(did.document.toString(), didFromPacket.first.toString())
    }

    @Test
    fun `to and from DNS packet - DID with types`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager, CreateDidDhtOptions(publish = false))

      val indexes = listOf(DidDhtTypeIndexing.Corporation, DidDhtTypeIndexing.SoftwarePackage)
      val packet = DidDht.toDnsPacket(did.document, indexes)
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDnsPacket(did.document.id, packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)
      assertNotNull(didFromPacket.second)

      assertEquals(did.document.toString(), didFromPacket.first.toString())
      assertEquals(indexes, didFromPacket.second)
    }

    @Test
    fun `to and from DNS packet - complex DID`() {
      val manager = InMemoryKeyManager()

      val otherKey = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(otherKey)
      val verificationMethodsToAdd: Iterable<Triple<Jwk, List<Purpose>, String?>> = listOf(
        Triple(publicKeyJwk, listOf(Purpose.Authentication, Purpose.AssertionMethod), null)
      )

      val serviceToAdd = Service.Builder()
        .id("test-service")
        .type("HubService")
        .serviceEndpoint(listOf("https://example.com/service", "https://example.com/service2"))
        .build()

      val opts = CreateDidDhtOptions(
        verificationMethods = verificationMethodsToAdd,
        services = listOf(serviceToAdd),
        controllers = listOf("did:dht:1bxdi3tbf1ud6cpk3ef9pz83erk9c6mmh877qfhfcd7ppzbgh7co"),
        alsoKnownAses = listOf("did:web:tbd.website"),
        publish = false
      )
      val did = DidDht.create(manager, opts)

      val packet = DidDht.toDnsPacket(did.document)
      assertNotNull(packet)

      val didFromPacket = DidDht.fromDnsPacket(did.document.id, packet)
      assertNotNull(didFromPacket)
      assertNotNull(didFromPacket.first)

      assertEquals(did.document.toString(), didFromPacket.first.toString())
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
      assertThrows<InvalidMethodNameException> { DidDht.validate("did:key:abcd123") }
    }

    @Test
    fun `throws exception if identifier cannot be zbase32 decoded`() {
      assertThrows<InvalidIdentifierException> { DidDht.validate("did:dht:abcd123") }
    }

    @Test
    fun `throws exception if decoded identifier is larger than 32 bytes`() {
      val kakaId = ZBase32.encode("Hakuna matata Hakuna Matata Hakuna Matata".toByteArray())
      assertThrows<InvalidIdentifierSizeException> { DidDht.validate("did:dht:$kakaId") }
    }

    @Test
    fun `throws exception if decoded identifier is smaller than 32 bytes`() {
      val kakaId = ZBase32.encode("a".toByteArray())
      assertThrows<InvalidIdentifierSizeException> { DidDht.validate("did:dht:$kakaId") }
    }
  }
}

private val mapper = Json.jsonMapper

class Web5TestVectorsDidDht {
  data class CreateTestInput(
    val identityPublicJwk: Map<String, Any>?,
    val additionalVerificationMethods: List<VerificationMethodInput>?,
    val services: List<Service>?,
    val controller: List<String>?,
    val alsoKnownAs: List<String>?,
  )

  data class ResolveTestInput(
    val didUri: String,
  )

  data class VerificationMethodInput(
    val jwk: Jwk,
    @JsonDeserialize(using = PurposesDeserializer::class)
    val purposes: List<Purpose>
  )


  @Test
  fun create() {
    val typeRef = object : TypeReference<TestVectors<CreateTestInput, DidDocument>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/did_dht/create.json"), typeRef)

    testVectors.vectors.forEach { vector ->
      val keyManager = spy(InMemoryKeyManager())
      val identityJwk = Json.parse<Jwk>(Json.stringify(vector.input.identityPublicJwk!!))
      val identityKeyId = keyManager.importKey(identityJwk)
      doReturn(identityKeyId).whenever(keyManager).generatePrivateKey(AlgorithmId.Ed25519)

      val verificationMethods = vector.input.additionalVerificationMethods?.map { verificationMethodInput ->
        Triple(verificationMethodInput.jwk, verificationMethodInput.purposes.toList(), null)
      }?.asIterable()

      val options = CreateDidDhtOptions(
        verificationMethods = verificationMethods,
        publish = false,
        services = vector.input.services,
        controllers = vector.input.controller,
        alsoKnownAses = vector.input.alsoKnownAs,
      )
      val didDht = DidDht.create(keyManager, options)
      assertEquals(
        JsonCanonicalizer(Json.stringify(vector.output!!)).encodedString,
        JsonCanonicalizer(Json.stringify(didDht.document)).encodedString,
        vector.description
      )
    }
  }

  @Test
  fun `resolve fails when identifier size is incorrect`() {
    val result = DidDht.resolve("did:dht:foo")
    assertEquals("invalidDid", result.didResolutionMetadata.error)
  }

  @Test
  fun `resolve fails with an invalid did`() {
    val result = DidDht.resolve("this-is-an-invalid-did")
    assertEquals("invalidDid", result.didResolutionMetadata.error)
  }

  @Test
  fun resolve() {
    val typeRef = object : TypeReference<TestVectors<ResolveTestInput, DidResolutionResult>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/did_dht/resolve.json"), typeRef)
    testVectors.vectors.forEach { vector ->
      val result = DidDhtApi {
        engine = MockEngine {
          when {
            it.url.encodedPath.matches("/\\w+".toRegex()) && it.method == HttpMethod.Get -> {
              respond("pkarr record not found", HttpStatusCode.NotFound)
            }

            else -> throw Exception("Unexpected request")
          }
        }
      }.resolve(vector.input.didUri)
      assertEquals(vector.output, result, vector.description)
    }
  }
}