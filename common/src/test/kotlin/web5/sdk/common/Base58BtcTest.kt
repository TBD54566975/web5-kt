package web5.sdk.common

import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class TestVector(val encoded: String, val decoded: () -> ByteArray)

// test vectors taken from https://datatracker.ietf.org/doc/html/draft-msporny-base58#section-5
val vectors = listOf(
  TestVector(
    encoded = "2NEpo7TZRRrLZSi2U",
    decoded = { "Hello World!".toByteArray() }
  ),
  TestVector(
    encoded = "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z",
    decoded = { "The quick brown fox jumps over the lazy dog.".toByteArray() }
  ),
  TestVector(
    encoded = "11233QC4",
    decoded = {
      val bytes = BigInteger.valueOf(0x287fb4cd).toByteArray()
      val bytesWithLeadingZeroes = ByteArray(bytes.size + 2) // add 2 leading 0 bytes

      bytes.copyInto(bytesWithLeadingZeroes, 2)
    }
  )
)

class Base58BtcTest {
  @Test
  fun `it works`() {
    for (vector in vectors) {
      val encoded = Base58Btc.encode(vector.decoded())
      assertEquals(vector.encoded, encoded)

      val decoded = Base58Btc.decode(encoded)
      assertContentEquals(vector.decoded(), decoded)
    }
  }
}