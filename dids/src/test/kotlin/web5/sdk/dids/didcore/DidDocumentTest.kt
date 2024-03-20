package web5.sdk.dids.didcore

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.jwk.DidJwk
import web5.sdk.dids.methods.key.DidKey
import java.security.SignatureException
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DidDocumentTest {

  @Nested
  inner class SelectVerificationMethodTest {

    @Test
    fun `selectVerificationMethod throws exception if vmMethod is empty`() {

      val doc = DidDocument("did:example:123")

      assertThrows<Exception> {
        doc.selectVerificationMethod(Purpose.AssertionMethod)
      }
    }

    @Test
    fun `selectVerificationMethod returns first vm`() {

      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)

      val vmList = listOf(
        VerificationMethod("id", "type", "controller", publicKeyJwk)
      )
      val doc = DidDocument(id = "did:example:123", verificationMethod = vmList)

      val vm = doc.selectVerificationMethod(null)
      assertEquals("id", vm.id)
      assertEquals("type", vm.type)
      assertEquals("controller", vm.controller)

    }

    @Test
    fun `selectVerificationMethod returns vm from the purpose specific method`() {

      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)

      val vmList = listOf(
        VerificationMethod("id", "type", "controller", publicKeyJwk)
      )
      val assertionMethods = listOf("id")
      val doc = DidDocument(
        id = "did:example:123",
        verificationMethod = vmList,
        assertionMethod = assertionMethods
      )

      val vm = doc.selectVerificationMethod(Purpose.AssertionMethod)
      assertEquals("id", vm.id)
      assertEquals("type", vm.type)
      assertEquals("controller", vm.controller)

    }

    @Test
    fun `selectVerificationMethod returns vm from the provided id`() {

      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)

      val vmList = listOf(
        VerificationMethod("id", "type", "controller", publicKeyJwk)
      )
      val assertionMethods = listOf("id")
      val doc = DidDocument(
        id = "did:example:123",
        verificationMethod = vmList,
        assertionMethod = assertionMethods
      )

      val vm = doc.selectVerificationMethod(ID("id"))
      assertEquals("id", vm.id)
      assertEquals("type", vm.type)
      assertEquals("controller", vm.controller)

    }

    @Test
    fun `selectVerificationMethod throws exception if id cannot be found`() {

      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)

      val vmList = listOf(
        VerificationMethod("id", "type", "controller", publicKeyJwk)
      )
      val doc = DidDocument(
        id = "did:example:123",
        verificationMethod = vmList
      )

      assertThrows<Exception> {
        doc.selectVerificationMethod(Purpose.AssertionMethod)
      }
    }

  }

  @Nested
  inner class GetAbsoluteResourceIDTest {
    @Test
    fun `getAbsoluteResourceID returns absolute resource id if passed in fragment`() {
      val doc = DidDocument("did:example:123")
      val resourceID = doc.getAbsoluteResourceID("#0")
      assertEquals("did:example:123#0", resourceID)
    }

    @Test
    fun `getAbsoluteResourceID returns absolute resource id if passed in full id`() {
      val doc = DidDocument("did:example:123")
      val resourceID = doc.getAbsoluteResourceID("did:example:123#1")
      assertEquals("did:example:123#1", resourceID)
    }
  }


  @Nested
  inner class FindAssertionMethodByIdTest {
    @Test
    fun `findAssertionMethodById throws exception if assertionMethod list is empty`() {
      val doc = DidDocument("did:example:123")

      assertThrows<SignatureException> {
        doc.findAssertionMethodById()
      }
    }

    @Test
    fun `findAssertionMethodById throws exception if assertionMethod does not have provided id`() {
      val assertionMethods = listOf("foo")

      val doc = DidDocument(id = "did:example:123", assertionMethod = assertionMethods)

      assertThrows<SignatureException> {
        doc.findAssertionMethodById("bar")
      }
    }

    @Test
    fun `findAssertionMethodById throws exception if id not found in verificationMethod`() {
      val assertionMethods = listOf("bar")
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)

      val vmList = listOf(
        VerificationMethod("foo", "type", "controller", publicKeyJwk)
      )

      val doc = DidDocument(id = "did:example:123", verificationMethod = vmList, assertionMethod = assertionMethods)

      assertThrows<SignatureException> {
        doc.findAssertionMethodById()
      }
    }

    // todo this test fails because of what i added to DidDocument#findAssertionMethodById()
    @Test
    fun `findAssertionMethodById returns assertion verification method if id is found`() {
      val assertionMethods = listOf("foo")
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)

      val vmList = listOf(
        VerificationMethod("foo", "type", "controller", publicKeyJwk)
      )

      val doc = DidDocument(id = "did:example:123", verificationMethod = vmList, assertionMethod = assertionMethods)

      val assertionMethod = doc.findAssertionMethodById("foo")
      assertEquals("foo", assertionMethod.id)
      assertEquals("type", assertionMethod.type)
      assertEquals("controller", assertionMethod.controller)
    }

    @Test
    fun `findAssertionMethodById works with default`() {
      val manager = InMemoryKeyManager()
      val bearerDid = DidKey.create(manager)

      val verificationMethod = DidKey.resolve(bearerDid.did.uri)
        .didDocument!!
        .findAssertionMethodById()
      assertEquals("${bearerDid.did.uri}#${Did.parse(bearerDid.did.uri).id}", verificationMethod.id)
    }

    @Test
    fun `findAssertionMethodById finds with id`() {
      val manager = InMemoryKeyManager()
      val bearerDid = DidKey.create(manager)

      val assertionMethodId = "${bearerDid.did.uri}#${Did.parse(bearerDid.did.uri).id}"
      val verificationMethod = DidKey.resolve(bearerDid.did.uri)
        .didDocument!!
        .findAssertionMethodById(assertionMethodId)
      assertEquals(assertionMethodId, verificationMethod.id)
    }

    @Test
    fun `findAssertionMethodById throws exception`() {
      val manager = InMemoryKeyManager()
      val bearerDid = DidKey.create(manager)

      val exception = assertThrows<SignatureException> {
        DidKey.resolve(bearerDid.did.uri)
          .didDocument!!
          .findAssertionMethodById("made up assertion method id")
      }
      assertContains(exception.message!!, "assertion method \"made up assertion method id\" not found")
    }

    @Test
    fun `findAssertionMethodById throws exception when no assertion methods are found`() {
      val manager = InMemoryKeyManager()
      val did = DidJwk.create(manager)
      val exception = assertThrows<SignatureException> {
        did.document.findAssertionMethodById("made up assertion method id")
      }
      assertEquals("assertion method \"made up assertion method id\" " +
        "not found in list of assertion methods", exception.message)
    }
  }

  @Nested
  inner class BuilderTest {
    @Test
    fun `builder creates a DidDocument with the provided id`() {

      val svc = Service.Builder()
        .id("service_id")
        .type("service_type")
        .serviceEndpoint(listOf("https://example.com"))
        .build()

      val doc = DidDocument.Builder()
        .id("did:ex:foo")
        .context(listOf("https://www.w3.org/ns/did/v1"))
        .controllers(listOf("did:ex:foo"))
        .alsoKnownAses(listOf("did:ex:bar"))
        .services(listOf(svc))
        .build()

      assertEquals("did:ex:foo", doc.id)
      assertEquals("https://www.w3.org/ns/did/v1", doc.context!!.first())
      assertEquals(listOf("did:ex:foo"), doc.controller)
      assertEquals(listOf("did:ex:bar"), doc.alsoKnownAs)
      assertEquals(listOf(svc), doc.service)
    }

    @Test
    fun `verificationMethodForPurposes builds lists`() {
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)
      val vm = VerificationMethod("foo", "type", "controller", publicKeyJwk)

      val doc = DidDocument.Builder()
        .id("did:ex:foo")
        .context(listOf("https://www.w3.org/ns/did/v1"))
        .verificationMethodForPurposes(vm,
          listOf(
            Purpose.AssertionMethod,
            Purpose.Authentication,
            Purpose.KeyAgreement,
            Purpose.CapabilityDelegation,
            Purpose.CapabilityInvocation)
        )
        .build()

      assertEquals(1, doc.verificationMethod?.size)
      assertEquals(1, doc.assertionMethod?.size)
      assertEquals(1, doc.authentication?.size)
      assertEquals(1, doc.keyAgreement?.size)
      assertEquals(1, doc.capabilityDelegation?.size)
      assertEquals(1, doc.capabilityInvocation?.size)

    }

    @Test
    fun `verificationMethodsForPurpose builds list for one purpose`() {
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)
      val vm = VerificationMethod("foo", "type", "controller", publicKeyJwk)

      val doc = DidDocument.Builder()
        .id("did:ex:foo")
        .context(listOf("https://www.w3.org/ns/did/v1"))
        .verificationMethodForPurposes(vm,listOf(Purpose.Authentication))
        .build()

      assertEquals(1, doc.verificationMethod?.size)
      assertEquals(1, doc.authentication?.size)
      assertNull(doc.keyAgreement)
      assertNull(doc.capabilityInvocation)
      assertNull(doc.capabilityDelegation)
      assertNull(doc.assertionMethod)
    }

    @Test
    fun `verificationMethodsForPurpose builds list when no purpose is passed in`() {
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)
      val vm = VerificationMethod("foo", "type", "controller", publicKeyJwk)

      val doc = DidDocument.Builder()
        .id("did:ex:foo")
        .context(listOf("https://www.w3.org/ns/did/v1"))
        .verificationMethodForPurposes(vm)
        .build()

      assertEquals(1, doc.verificationMethod?.size)
      assertNull(doc.authentication)
      assertNull(doc.keyAgreement)
      assertNull(doc.capabilityInvocation)
      assertNull(doc.capabilityDelegation)
      assertNull(doc.assertionMethod)
    }

    @Test
    fun `verificationMethodIdsForPurpose builds list for one purpose`() {
      val doc = DidDocument.Builder()
        .id("did:ex:foo")
        .context(listOf("https://www.w3.org/ns/did/v1"))
        .verificationMethodIdsForPurpose(mutableListOf("keyagreementId"), Purpose.KeyAgreement)
        .build()

      assertEquals(1, doc.keyAgreement?.size)
      assertNull(doc.verificationMethod)
      assertNull(doc.authentication)
      assertNull(doc.capabilityInvocation)
      assertNull(doc.capabilityDelegation)
      assertNull(doc.assertionMethod)
    }
  }
}
