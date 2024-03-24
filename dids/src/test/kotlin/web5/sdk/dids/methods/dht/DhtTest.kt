package web5.sdk.dids.methods.dht

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.Ed25519
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.dht.DhtClient.Companion.bencode
import web5.sdk.dids.methods.dht.DidDht.Default.suffix
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DhtTest {
  @Nested
  inner class BencodeTest {
    @Test
    fun `encode an empty byte array`() {
      val input = ByteArray(0)
      val expected = "0:".toByteArray()
      val result = bencode(input)
      assertArrayEquals(expected, result)
    }

    @Test
    fun `encode a byte array with a single byte`() {
      val input = byteArrayOf(65)
      val expected = "1:A".toByteArray()
      val result = bencode(input)
      assertArrayEquals(expected, result)
    }

    @Test
    fun `encode a byte array with multiple bytes`() {
      val input = byteArrayOf(65, 66, 67)
      val expected = "3:ABC".toByteArray()
      val result = bencode(input)
      assertArrayEquals(expected, result)
    }

    @Test
    fun `encode a byte array with special characters`() {
      val input = byteArrayOf(35, 36, 37)
      val expected = "3:#$%".toByteArray()
      val result = bencode(input)
      assertArrayEquals(expected, result)
    }

    @Test
    fun `encode a very large byte array`() {
      val input = ByteArray(1_000_000) { 65 }
      val expected = "1000000:${"A".repeat(1_000_000)}".toByteArray()
      val result = bencode(input)
      assertArrayEquals(expected, result)
    }
  }

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
      manager.importKey(privateKey)

      val bep44SignedMessage = DhtClient.signBep44Message(
        manager,
        privateKey.kid ?: privateKey.computeThumbprint(),
        seq,
        v
      )
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
      val keyAlias = manager.generatePrivateKey(AlgorithmId.Ed25519)

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
      val keyAlias = manager.generatePrivateKey(AlgorithmId.secp256k1)

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
      val diddht = DidDhtApi {}
      val did = diddht.create(manager)

      val kid = did.document.verificationMethod?.first()?.publicKeyJwk?.kid
        ?: did.document.verificationMethod?.first()?.publicKeyJwk?.computeThumbprint()
      assertNotNull(kid)

      val message = did.document.let { diddht.toDnsPacket(it) }
      assertNotNull(message)

      val bep44Message = DhtClient.createBep44PutRequest(manager, kid, message)
      assertNotNull(bep44Message)

      val parsedMessage = DhtClient.parseBep44GetResponse(bep44Message)
      assertNotNull(parsedMessage)

      assertEquals(message.toString(), parsedMessage.toString())
    }

    @Test
    fun `put and get a bep44 message to a pkarr relay`() {
      val dhtClient = DhtClient()
      val manager = InMemoryKeyManager()
      val diddht = DidDhtApi {}
      val bearerDid = diddht.create(manager)

      val kid = bearerDid.document.verificationMethod?.first()?.publicKeyJwk?.kid
        ?: bearerDid.document.verificationMethod?.first()?.publicKeyJwk?.computeThumbprint()
      assertNotNull(kid)

      val message = bearerDid.document.let { diddht.toDnsPacket(it) }
      assertNotNull(message)

      val bep44Message = DhtClient.createBep44PutRequest(manager, kid, message)
      assertNotNull(bep44Message)

      assertDoesNotThrow { dhtClient.pkarrPut(suffix(bearerDid.uri), bep44Message) }

      val retrievedMessage = assertDoesNotThrow { dhtClient.pkarrGet(suffix(bearerDid.uri)) }
      assertNotNull(retrievedMessage)
    }

    @Test
    fun `bad pkarr put`() {
      val bep = Bep44Message(
        v = "v".toByteArray(),
        sig = "s".repeat(64).toByteArray(),
        k = "k".repeat(32).toByteArray(),
        seq = 1
      )

      val exception = assertThrows<IllegalArgumentException> { DhtClient().pkarrPut("bad", bep) }
      assertEquals("Identifier must be a z-base-32 encoded Ed25519 public key", exception.message)
    }

    @Test
    fun `bad pkarr get`() {

      val exception = assertThrows<IllegalArgumentException> { DhtClient().pkarrGet("bad") }
      assertEquals("Identifier must be a z-base-32 encoded Ed25519 public key", exception.message)
    }
  }
}