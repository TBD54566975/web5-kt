package web5.sdk.dids.methods.dht

import com.nimbusds.jose.jwk.Curve
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.Ed25519
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.Secp256k1
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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

      val bep44SignedMessage = DhtClient.signBep44Message(manager, privateKey.keyID, seq, v)
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

      val bep44SignedMessage = DhtClient.signBep44Message(manager, keyAlias, seq, v)
      assertNotNull(bep44SignedMessage)

      val toVerify = Bep44Message(
        v = v,
        sig = bep44SignedMessage.sig,
        k = bep44SignedMessage.k,
        seq = bep44SignedMessage.seq
      )

      assertDoesNotThrow { DhtClient.verifyBep44Message(toVerify) }
      assertTrue { toVerify == bep44SignedMessage }
      assertTrue { toVerify.hashCode() == bep44SignedMessage.hashCode() }
    }

    @Test
    fun `sign BEP44 message with wrong key type`() {
      val manager = InMemoryKeyManager()
      val keyAlias = manager.generatePrivateKey(Secp256k1.algorithm, Curve.SECP256K1)

      val seq = 1L
      val v = "Hello World!".toByteArray()

      val exception = assertThrows<IllegalArgumentException> {
        val bep44SignedMessage = DhtClient.signBep44Message(manager, keyAlias, seq, v)
        assertNotNull(bep44SignedMessage)
      }
      assertEquals("Must supply an Ed25519 key", exception.message)
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

      val bep44Message = DhtClient.createBep44PutRequest(manager, kid, message)
      assertNotNull(bep44Message)

      val parsedMessage = DhtClient.parseBep44GetResponse(bep44Message)
      assertNotNull(parsedMessage)

      assertEquals(message.toString(), parsedMessage.toString())
    }

    @Test
    fun `put and get a bep44 message to a pkarr relay`() {
      val dht = DhtClient(engine = mockEngine())
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)

      require(did.didDocument != null)

      val kid = did.didDocument!!.verificationMethods?.first()?.publicKeyJwk?.get("kid")?.toString()
      assertNotNull(kid)

      val message = did.didDocument?.let { DidDht.toDnsPacket(it) }
      assertNotNull(message)

      val bep44Message = DhtClient.createBep44PutRequest(manager, kid, message)
      assertNotNull(bep44Message)

      assertDoesNotThrow { dht.pkarrPut(did.suffix(), bep44Message) }

      val retrievedMessage = assertDoesNotThrow { dht.pkarrGet(did.suffix()) }
      assertNotNull(retrievedMessage)
    }

    @Test
    fun `bad pkarr put`() {
      val dht = DhtClient(engine = mockEngine())
      val manager = InMemoryKeyManager()
      val did = DidDht.create(manager)

      require(did.didDocument != null)

      val kid = did.didDocument!!.verificationMethods?.first()?.publicKeyJwk?.get("kid")?.toString()
      assertNotNull(kid)

      val message = did.didDocument?.let { DidDht.toDnsPacket(it) }
      assertNotNull(message)

      val bep44Message = DhtClient.createBep44PutRequest(manager, kid, message)
      assertNotNull(bep44Message)

      val exception = assertThrows<IllegalArgumentException> { dht.pkarrPut("bad", bep44Message) }
      assertEquals("Identifier must be a z-base-32 encoded Ed25519 public key", exception.message)
    }

    @Test
    fun `bad pkarr get`() {
      val dht = DhtClient(engine = mockEngine())

      val exception = assertThrows<IllegalArgumentException> { dht.pkarrGet("bad") }
      assertEquals("Identifier must be a z-base-32 encoded Ed25519 public key", exception.message)
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun mockEngine() = MockEngine { request ->
      val hexResponse = "26a2d522395f6ed4218724add94c8bf1577be09b5055d8f43b74d7167c3e8294e7e360821967a84134e90863812c" +
        "21393f7f23f1c4f047b97ef6f22c8c34eb0f00000000659da364000004000000000200000000035f6b30045f64696400001000010000" +
        "1c2000383769643d23303b743d303b6b3d424d74456e4369386f6d586a4f30567953303976764458382d3432386a6954464c38516c4a" +
        "6b6834464245c0100010000100001c20002322766d3d6b303b617574683d6b303b61736d3d6b303b696e763d6b303b64656c3d6b30"

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
}