package web5.sdk.dids.methods.dht

import com.nimbusds.jose.jwk.Curve
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.Ed25519
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.Secp256k1
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
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
      // a hex response getting a pkarr did:dht packet from a gateway
      val hexResponse = "2099f1ddf2e14c3fa693e89070cceb34d597d456e34ca32a07171badd734d62bfabac20b70e2751" +
        "d31acd65d76e22ec0b66a0a7029064adccaf533ddd81e930a00000000655e4531000004000000000200000000035f6b3" +
        "0045f646964000010000100001c2000373669643d302c743d302c6b3d794873562d64474b4e7947714964434c71624e5f" +
        "345358526936385249557146695a4a5172366946665930c0100010000100001c20002322766d3d6b303b617574683d6b303" +
        "b61736d3d6b303b696e763d6b303b64656c3d6b30"

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