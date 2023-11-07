package web5.sdk.dids.methods.dht

import com.turn.ttorrent.bcodec.BEncoder
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import web5.sdk.crypto.Ed25519
import java.io.ByteArrayOutputStream
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.text.hexToByteArray

class PkarrTest {

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

      val bep44SignedMessage = Pkarr.signBep44Message(privateKey, seq, v)
      assertNotNull(bep44SignedMessage)

      assertEquals("48656c6c6f20576f726c6421", bep44SignedMessage.v.toHexString())
      assertEquals("c1dc657a17f54ca51933b17b7370b87faae10c7edd560fd4baad543869e30e8154c510f4d0b0d94d1e683891b06a07cecd9f0be325fe8f8a0466fe38011b2d0a", bep44SignedMessage.sig.toHexString())
      assertEquals("796f7457532cd39697f4fccd1a2d7074e6c1f6c59e6ecf5dc16c8ecd6e3fea6c", bep44SignedMessage.k.toHexString())
    }

    @Test
    fun `sign and verify a BEP44 message`() {
      val privateKey = Ed25519.generatePrivateKey()

      val seq = 1L
      val v = "Hello World!".toByteArray()

      val bep44SignedMessage = Pkarr.signBep44Message(privateKey, seq, v)
      assertNotNull(bep44SignedMessage)

      val verified = Pkarr.verifyBep44Message(bep44SignedMessage)
      assertEquals(true, verified)
    }
  }
}