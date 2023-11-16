package web5.sdk.dids.methods.key

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.DidResolvers
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// TODO: use all relevant test vectors from https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/
class DidKeyTest {
  @Nested
  inner class CreateTest {
    @Test
    fun `it works`() {
      val manager = InMemoryKeyManager()
      val did = DidKey.create(manager)

      val didResolutionResult = DidResolvers.resolve(did.uri)
      val verificationMethod = didResolutionResult.didDocument.allVerificationMethods[0]

      require(verificationMethod != null) { "no verification method found" }

      val jwk = JWK.parse(verificationMethod.publicKeyJwk)
      val keyAlias = did.keyManager.getDeterministicAlias(jwk)
      val publicKey = did.keyManager.getPublicKey(keyAlias)
    }
  }

  @Test
  fun `load fails when key manager does not contain private key`() {
    val manager = InMemoryKeyManager()
    val exception = assertThrows<IllegalArgumentException> {
      DidKey.load("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", manager)
    }
    assertEquals("key with alias 9ZP03Nu8GrXPAUkbKNxHOKBzxPX83SShgFkRNK-f2lw not found", exception.message)
  }

  @Test
  fun `load returns instance when key manager contains private key`() {
    val manager = InMemoryKeyManager()
    val did = DidKey.create(manager)
    val didKey = DidKey.load(did.uri, manager)
    assertEquals(did.uri, didKey.uri)
  }

  @Test
  fun `throws exception when loading a different type of did`() {
    val manager = InMemoryKeyManager()
    val did = DidKey.create(manager)
    val exception = assertThrows<IllegalArgumentException> {
      DidKey.load(did.uri.replace("key", "ion"), manager)
    }
    assertTrue(exception.message!!.startsWith("did must start with the prefix \"id:key\""))
  }

  @Nested
  inner class ResolveTest {
    @Test
    fun `resolving a secp256k1 DID works`() {
      // test vector taken from: https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/secp256k1.json#L202C4-L257
      val did = "did:key:zQ3shjmnWpSDEbYKpaFm4kTs9kXyqG6N2QwCYHNPP4yubqgJS"
      val result = DidKey.resolve(did)
      assertNotNull(result)

      val didDocument = result.didDocument
      assertNotNull(didDocument)
      assertEquals(did, didDocument.id.toString())
      assertEquals(1, didDocument.allVerificationMethods.size)
      assertEquals(1, didDocument.assertionMethodVerificationMethods.size)
      assertEquals(1, didDocument.authenticationVerificationMethods.size)
      assertEquals(1, didDocument.capabilityDelegationVerificationMethods.size)
      assertEquals(1, didDocument.capabilityInvocationVerificationMethods.size)
      assertEquals(1, didDocument.keyAgreementVerificationMethods.size)

      val verificationMethod = didDocument.verificationMethods.first()
      assertEquals(
        "did:key:zQ3shjmnWpSDEbYKpaFm4kTs9kXyqG6N2QwCYHNPP4yubqgJS#zQ3shjmnWpSDEbYKpaFm4kTs9kXyqG6N2QwCYHNPP4yubqgJS",
        verificationMethod.id.toString()
      )

      // Note: cannot run the controller assertion because underlying lib enforces JSON-LD @context
      // despite it not being a required field
      // assertEquals(did, verificationMethod.controller.toString())
      assertEquals("JsonWebKey2020", verificationMethod.type)
      assertNotNull(verificationMethod.publicKeyJwk)

      val publicKeyJwk = JWK.parse(verificationMethod.publicKeyJwk) // validates
      assertTrue(publicKeyJwk is ECKey)

      assertEquals(publicKeyJwk.algorithm, JWSAlgorithm.ES256K)
      assertEquals(Curve.SECP256K1, publicKeyJwk.curve)
      assertEquals("TEIJN9vnTq1EXMkqzo7yN_867-foKc2pREv45Fw_QA8", publicKeyJwk.x.toString())
      assertEquals("9yiymlzdxKCiRbYq7p-ArRB-C1ytjHE-eb7RDTi6rVc", publicKeyJwk.y.toString())

    }
  }

  @Nested
  inner class ImportExportTest {
    @Test
    fun `InMemoryKeyManager export then re-import doesn't throw exception`() {
      val jsonMapper = ObjectMapper()
        .registerKotlinModule()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL)

      assertDoesNotThrow {
        val km = InMemoryKeyManager()
        val did = DidKey.create(km)

        val keySet = km.export()
        val serializedKeySet = jsonMapper.writeValueAsString(keySet)
        val didUri = did.uri

        val jsonKeySet: List<Map<String, Any>> = jsonMapper.readValue(serializedKeySet)
        val km2 = InMemoryKeyManager()
        km2.import(jsonKeySet)

        DidKey.load(did = didUri, keyManager = km2)
      }
    }
  }
}