package web5.sdk.dids.methods.dht

import com.nimbusds.jose.jwk.Curve
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.crypto.Ed25519
import web5.sdk.crypto.InMemoryKeyManager
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.text.hexToByteArray

class DhtTest {

  @Nested
  inner class Bep44Test {

    // This test vector matches an example from the go implementation
    // https://github.com/TBD54566975/did-dht-method/blob/main/impl/pkg/dht/dht_test.go#L47
    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun `sign BEP44 message - known test vector`() {
      val privateKeyBytes = "3077903f62fbcff4bdbae9b5129b01b78ab87f68b8b3e3d332f14ca13ad53464".hexToByteArray()
      val privateKey = Ed25519.bytesToPrivateKey(privateKeyBytes)

      val seq = 1L
      val v = "Hello World!".toByteArray()

      val manager = InMemoryKeyManager()
      manager.import(privateKey)

      val bep44SignedMessage = Dht.signBep44Message(manager, privateKey.keyID, seq, v)
      assertNotNull(bep44SignedMessage)

      assertEquals("48656c6c6f20576f726c6421", bep44SignedMessage.v.toHexString())
      assertEquals(
        "c1dc657a17f54ca51933b17b7370b87faae10c7edd560fd4baad543869e30e8154c510f4d0b0d94d1e683891b06a07cec" +
          "d9f0be325fe8f8a0466fe38011b2d0a",
        bep44SignedMessage.sig.toHexString()
      )
      assertEquals(
        "796f7457532cd39697f4fccd1a2d7074e6c1f6c59e6ecf5dc16c8ecd6e3fea6c",
        bep44SignedMessage.k.toHexString()
      )
    }

    @Test
    fun `sign and verify a BEP44 message`() {
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(Ed25519.algorithm, Curve.Ed25519)

      val seq = 1L
      val v = "Hello World!".toByteArray()

      val bep44SignedMessage = Dht.signBep44Message(manager, keyAlias, seq, v)
      assertNotNull(bep44SignedMessage)

      val toVerify = Bep44Message(
        v = v,
        sig = bep44SignedMessage.sig,
        k = bep44SignedMessage.k,
        seq = bep44SignedMessage.seq
      )

      assertDoesNotThrow { Dht.verifyBep44Message(toVerify) }
    }
  }

  @Nested
  inner class DhtTest {
    @Test
    fun `create and parse a bep44 put request`() {
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)

      require(did.didDocument != null)

      val kid = did.didDocument!!.verificationMethods?.first()?.publicKeyJwk?.get("kid")?.toString()
      assertNotNull(kid)

      val message = did.didDocument?.let { DidDht.toDnsPacket(it) }
      assertNotNull(message)

      val bep44Message = Dht.createBep44PutRequest(manager, kid, message)
      assertNotNull(bep44Message)

      val parsedMessage = Dht.parseBep44GetResponse(bep44Message)
      assertNotNull(parsedMessage)

      assertEquals(message.toString(), parsedMessage.toString())
    }

    @Test
    fun `put and get a bep44 message to a pkarr relay`() {
      val dht = Dht()
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)

      require(did.didDocument != null)

      val kid = did.didDocument!!.verificationMethods?.first()?.publicKeyJwk?.get("kid")?.toString()
      assertNotNull(kid)

      val message = did.didDocument?.let { DidDht.toDnsPacket(it) }
      assertNotNull(message)

      val bep44Message = Dht.createBep44PutRequest(manager, kid, message)
      assertNotNull(bep44Message)

      assertDoesNotThrow { dht.pkarrPut(did.suffix(), bep44Message) }

      // sleep 10 seconds to wait for propagation
      Thread.sleep(10000)

      val retrievedMessage = assertDoesNotThrow { dht.pkarrGet(did.suffix()) }
      assertNotNull(retrievedMessage)
    }
  }
}