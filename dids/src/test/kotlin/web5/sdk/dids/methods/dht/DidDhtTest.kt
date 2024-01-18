package web5.sdk.dids.methods.dht

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import foundation.identity.did.DIDDocument
import foundation.identity.did.Service
import foundation.identity.did.parser.ParserException
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import web5.sdk.common.ZBase32
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.PublicKeyPurpose
import web5.sdk.dids.exceptions.InvalidIdentifierException
import web5.sdk.dids.exceptions.InvalidIdentifierSizeException
import web5.sdk.dids.exceptions.InvalidMethodNameException
import web5.sdk.testing.TestVectors
import java.io.File
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
      val publicKeyJwk2 = ECKeyGenerator(Curve.P_256).generate().toPublicJWK()
      val verificationMethodsToAdd: Iterable<Triple<JWK, Array<PublicKeyPurpose>, String?>> = listOf(
        Triple(
          publicKeyJwk,
          arrayOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.ASSERTION_METHOD),
          "did:web:tbd.website"
        ),
        Triple(
          publicKeyJwk2,
          arrayOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.ASSERTION_METHOD),
          "did:web:tbd.website"
        )
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
      assertEquals(3, did.didDocument!!.verificationMethods.size)
      assertEquals(3, did.didDocument!!.assertionMethodVerificationMethods.size)
      assertEquals(3, did.didDocument!!.authenticationVerificationMethods.size)
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
      val knownDid = "did:dht:qd5pz3sfsmhwhts9auy1qe6cwniemss4bpm3qxm8modtr148z17y"

      assertDoesNotThrow {
        val result = api.resolve(knownDid)
        assertNotNull(result)
        assertNotNull(result.didDocument)
        assertEquals(knownDid, result.didDocument!!.id.toString())
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
      val verificationMethodsToAdd: Iterable<Triple<JWK, Array<PublicKeyPurpose>, String?>> = listOf(
        Triple(publicKeyJwk, arrayOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.ASSERTION_METHOD), null)
      )

      val serviceToAdd = Service.builder()
        .id(URI("test-service"))
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

private val mapper = jacksonObjectMapper()

class Web5TestVectorsDidDhtTest {
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
    val jwk: Map<String, Any>,
    val purposes: List<PublicKeyPurpose>
  )


  @Test
  fun create() {
    val typeRef = object : TypeReference<TestVectors<CreateTestInput, DIDDocument>>() {}
    val testVectors = mapper.readValue(File("../test-vectors/did_dht/create.json"), typeRef)

    testVectors.vectors.forEach { vector ->
      val keyManager = spy(InMemoryKeyManager())
      val identityKeyId = keyManager.import(listOf(vector.input.identityPublicJwk!!)).first()
      doReturn(identityKeyId).whenever(keyManager).generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)

      val verificationMethods = vector.input.additionalVerificationMethods?.map { verificationMethodInput ->
        val jwk = JWK.parse(verificationMethodInput.jwk)
        Triple(jwk, verificationMethodInput.purposes.toTypedArray(), null)
      }
      val options = CreateDidDhtOptions(
        verificationMethods = verificationMethods,
        publish = false,
        services = vector.input.services,
        controllers = vector.input.controller,
        alsoKnownAses = vector.input.alsoKnownAs,
      )
      val didDht = DidDht.create(keyManager, options)
      assertEquals(
        JsonCanonicalizer(vector.output?.toJson()).encodedString,
        JsonCanonicalizer(didDht.didDocument!!.toCustomJson()).encodedString,
        vector.description
      )
    }
  }

  @Test
  fun resolve() {
    val typeRef = object : TypeReference<TestVectors<ResolveTestInput, DidResolutionResult>>() {}
    val testVectors = mapper.readValue(File("../test-vectors/did_dht/resolve.json"), typeRef)
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

// The test vectors assume the property "controller" is rendered as a string (vs. an array of strings) when there is
// only one controller.
private fun DIDDocument.toCustomJson(): String? {
  val jsonObject = this.jsonObject.toMutableMap()
  if (jsonObject["controller"] is List<*> && (jsonObject["controller"] as List<*>).size == 1) {
    jsonObject["controller"] = (jsonObject["controller"] as List<*>).single()
  }
  return mapper.writeValueAsString(jsonObject)
}
