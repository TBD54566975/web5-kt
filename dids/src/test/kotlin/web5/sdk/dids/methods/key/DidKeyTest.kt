package web5.sdk.dids.methods.key

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.Jwa
import web5.sdk.crypto.JwaCurve
import web5.sdk.dids.DidResolvers
import web5.sdk.dids.exceptions.InvalidMethodNameException
import web5.sdk.dids.methods.dht.DidDht
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
      val bearerDid = DidKey.create(manager)

      val didResolutionResult = DidResolvers.resolve(bearerDid.did.uri)

      assertNotNull(didResolutionResult.didDocument)
      val verificationMethod = didResolutionResult.didDocument!!.verificationMethod?.get(0)

      val jwk = verificationMethod?.publicKeyJwk
      assertNotNull(jwk)

      val keyAlias = bearerDid.keyManager.getDeterministicAlias(jwk)
      val publicKey = bearerDid.keyManager.getPublicKey(keyAlias)
      assertNotNull(jwk)
      assertNotNull(keyAlias)
      assertNotNull(publicKey)

    }
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
      assertEquals(did, didDocument.id)
      assertEquals(1, didDocument.verificationMethod?.size)
      assertEquals(1, didDocument.assertionMethod?.size)
      assertEquals(1, didDocument.authentication?.size)
      assertEquals(1, didDocument.capabilityDelegation?.size)
      assertEquals(1, didDocument.capabilityInvocation?.size)
      assertEquals(1, didDocument.keyAgreement?.size)

      val verificationMethod = didDocument.verificationMethod?.first()
      assertNotNull(verificationMethod)

      assertEquals(
        "did:key:zQ3shjmnWpSDEbYKpaFm4kTs9kXyqG6N2QwCYHNPP4yubqgJS#zQ3shjmnWpSDEbYKpaFm4kTs9kXyqG6N2QwCYHNPP4yubqgJS",
        verificationMethod.id
      )

      // Note: cannot run the controller assertion because underlying lib enforces JSON-LD @context
      // despite it not being a required field
      // assertEquals(did, verificationMethod.controller.toString())
      assertEquals("JsonWebKey2020", verificationMethod.type)
      assertNotNull(verificationMethod.publicKeyJwk)

      val publicKeyJwk = verificationMethod.publicKeyJwk // validates
      assertTrue(publicKeyJwk?.kty == "EC")

      assertEquals(publicKeyJwk?.alg, Jwa.ES256K.name)
      assertEquals(JwaCurve.secp256k1.name, publicKeyJwk?.crv)
      assertEquals("TEIJN9vnTq1EXMkqzo7yN_867-foKc2pREv45Fw_QA8", publicKeyJwk?.x.toString())
      assertEquals("9yiymlzdxKCiRbYq7p-ArRB-C1ytjHE-eb7RDTi6rVc", publicKeyJwk?.y.toString())

    }
  }

  @Nested
  inner class ImportTest {
    @Test
    fun `BearerDid export then re-import doesn't throw exception`() {
      assertDoesNotThrow {
        val km = InMemoryKeyManager()
        val bearerDid = DidKey.create(km)

        val portableDid = bearerDid.export()
        val km2 = InMemoryKeyManager()
        DidKey.import(portableDid, km2)
      }
    }

    @Test
    fun `importing a portable did key did works`() {
      val manager = InMemoryKeyManager()
      val bearerDid = DidKey.create(manager)
      val portableDid = bearerDid.export()
      val importedDid = DidKey.import(portableDid, manager)
      assertEquals(bearerDid.did.uri, importedDid.did.uri)
    }

    @Test
    fun `importing a did with wrong method name throws exception`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)
      val portableDid = did.export()
      assertThrows<InvalidMethodNameException> {
        DidKey.import(portableDid, manager)
      }
    }
  }
}