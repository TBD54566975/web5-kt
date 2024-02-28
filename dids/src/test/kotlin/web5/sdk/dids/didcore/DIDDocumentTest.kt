package web5.sdk.dids.didcore

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.InMemoryKeyManager
import java.security.SignatureException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DIDDocumentTest {

  @Nested
  inner class SelectVerificationMethodTest {

    @Test
    fun `selectVerificationMethod throws exception if vmMethod is empty`() {

      val doc = DIDDocument("did:example:123")

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
      val doc = DIDDocument(id = "did:example:123", verificationMethod = vmList)

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
      val doc = DIDDocument(
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
      val doc = DIDDocument(
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
      val doc = DIDDocument(
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
      val doc = DIDDocument("did:example:123")
      val resourceID = doc.getAbsoluteResourceID("#0")
      assertEquals("did:example:123#0", resourceID)
    }

    @Test
    fun `getAbsoluteResourceID returns absolute resource id if passed in full id`() {
      val doc = DIDDocument("did:example:123")
      val resourceID = doc.getAbsoluteResourceID("did:example:123#1")
      assertEquals("did:example:123#1", resourceID)
    }
  }


  @Nested
  inner class FindAssertionMethodByIdTest {
    @Test
    fun `findAssertionMethodById throws exception if assertionMethod list is empty`() {
      val doc = DIDDocument("did:example:123")

      assertThrows<SignatureException> {
        doc.findAssertionMethodById()
      }
    }

    @Test
    fun `findAssertionMethodById throws exception if assertionMethod does not have provided id`() {
      val assertionMethods = listOf("foo")

      val doc = DIDDocument(id = "did:example:123", assertionMethod = assertionMethods)

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

      val doc = DIDDocument(id = "did:example:123", verificationMethod = vmList, assertionMethod = assertionMethods)

      assertThrows<SignatureException> {
        doc.findAssertionMethodById()
      }
    }

    @Test
    fun `findAssertionMethodById returns assertion verification method if id is found`() {
      val assertionMethods = listOf("foo")
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
      val publicKeyJwk = manager.getPublicKey(keyAlias)

      val vmList = listOf(
        VerificationMethod("foo", "type", "controller", publicKeyJwk)
      )

      val doc = DIDDocument(id = "did:example:123", verificationMethod = vmList, assertionMethod = assertionMethods)

      val assertionMethod = doc.findAssertionMethodById("foo")
      assertEquals("foo", assertionMethod.id)
      assertEquals("type", assertionMethod.type)
      assertEquals("controller", assertionMethod.controller)
    }
  }

  @Nested
  inner class BuilderTest {
    @Test
    fun `builder creates a DIDDocument with the provided id`() {

      val svc = Service.Builder()
        .id("service_id")
        .type("service_type")
        .serviceEndpoint(listOf("https://example.com"))
        .build()

      val doc = DIDDocument.Builder()
        .id("did:ex:foo")
        .context("https://www.w3.org/ns/did/v1")
        .controllers(listOf("did:ex:foo"))
        .alsoKnownAses(listOf("did:ex:bar"))
        .services(listOf(svc))
        .build()

      assertEquals("did:ex:foo", doc.id)
      assertEquals("https://www.w3.org/ns/did/v1", doc.context)
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

      val doc = DIDDocument.Builder()
        .id("did:ex:foo")
        .context("https://www.w3.org/ns/did/v1")
        .verificationMethodForPurposes(vm, listOf(Purpose.AssertionMethod, Purpose.Authentication, Purpose.KeyAgreement, Purpose.CapabilityDelegation, Purpose.CapabilityInvocation))
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

      val doc = DIDDocument.Builder()
        .id("did:ex:foo")
        .context("https://www.w3.org/ns/did/v1")
        .verificationMethodsForPurpose(mutableListOf(vm),Purpose.Authentication)
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

      val doc = DIDDocument.Builder()
        .id("did:ex:foo")
        .context("https://www.w3.org/ns/did/v1")
        .verificationMethodsForPurpose(mutableListOf(vm))
        .build()

      assertEquals(1, doc.verificationMethod?.size)
      assertNull(doc.authentication)
      assertNull(doc.keyAgreement)
      assertNull(doc.capabilityInvocation)
      assertNull(doc.capabilityDelegation)
      assertNull(doc.assertionMethod)
    }
  }
}
