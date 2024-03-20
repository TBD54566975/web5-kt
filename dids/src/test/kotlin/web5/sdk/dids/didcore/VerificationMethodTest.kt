package web5.sdk.dids.didcore

import com.nimbusds.jose.jwk.JWK
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.InMemoryKeyManager
import kotlin.test.Test
import kotlin.test.assertEquals

class VerificationMethodTest {

  var publicKey: JWK? = null

  @BeforeEach
  fun setUp() {
    val manager = InMemoryKeyManager()
    val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)
    publicKey = manager.getPublicKey(keyAlias)
  }
  @Test
  fun `Builder works`() {
    val vm = VerificationMethod.Builder()
      .id("did:example:123#key-1")
      .type("IdentityKey")
      .controller("did:example:123")
      .publicKeyJwk(publicKey!!)
      .build()
    assertEquals("did:example:123#key-1", vm.id)
    assertEquals("IdentityKey", vm.type)
    assertEquals("did:example:123", vm.controller)
    assertEquals(publicKey, vm.publicKeyJwk)
    assertEquals(
      "VerificationMethod(" +
        "id='did:example:123#key-1', " +
        "type='IdentityKey', " +
        "controller='did:example:123', " +
        "publicKeyJwk=$publicKey)",
      vm.toString()
    )
  }

  @Test
  fun `build() throws exception if id is not set`() {
    assertThrows<IllegalStateException> {
      VerificationMethod.Builder()
        .type("IdentityKey")
        .controller("did:example:123")
        .publicKeyJwk(publicKey!!)
        .build()
    }
  }

  @Test
  fun `build() throws exception if type is not set`() {
    assertThrows<IllegalStateException> {
      VerificationMethod.Builder()
        .id("did:example:123#key-1")
        .controller("did:example:123")
        .publicKeyJwk(publicKey!!)
        .build()
    }
  }

  @Test
  fun `build() throws exception if controller is not set`() {
    assertThrows<IllegalStateException> {
      VerificationMethod.Builder()
        .id("did:example:123#key-1")
        .type("IdentityKey")
        .publicKeyJwk(publicKey!!)
        .build()
    }
  }

  @Test
  fun `build() throws exception if publicKeyJwk is not set`() {
    assertThrows<IllegalStateException> {
      VerificationMethod.Builder()
        .id("did:example:123#key-1")
        .type("IdentityKey")
        .controller("did:example:123")
        .build()
    }
  }

}