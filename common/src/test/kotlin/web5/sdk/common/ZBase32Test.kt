package web5.sdk.common

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

val zbase32Vectors = listOf(
  TestVector(
    encoded = "",
    decoded = { "".toByteArray() }
  ),
  TestVector(
    encoded = "y",
    decoded = { byteArrayOf(0) }
  ),
  TestVector(
    encoded = "o",
    decoded = { byteArrayOf(128.toByte()) }
  ),
  TestVector(
    encoded = "e",
    decoded = { byteArrayOf(64.toByte()) }
  ),
  TestVector(
    encoded = "a",
    decoded = { byteArrayOf(192.toByte()) }
  ),
  TestVector(
    encoded = "on",
    decoded = { byteArrayOf(128.toByte(), 128.toByte()) }
  ),
//  TestVector(
//    encoded = "tgre",
//    decoded = { byteArrayOf(139.toByte(), 136.toByte(), 128.toByte()) }
//  ),
//  TestVector(
//    encoded = "6n9hq",
//    decoded = { byteArrayOf(240.toByte(), 191.toByte(), 199.toByte()) }
//  ),
//  TestVector(
//    encoded = "4t7ye",
//    decoded = { byteArrayOf(212.toByte(), 122.toByte(), 4.toByte()) }
//  ),
//  TestVector(
//    encoded = "yy",
//    decoded = { byteArrayOf(0, 0) }
//  ),
//  TestVector(
//    encoded = "ab3sr1ix8fhfnuzaeo75fkn3a7xh8udk6jsiiko",
//    decoded = { byteArrayOf(
//      0xc0.toByte(), 0x73.toByte(), 0x62.toByte(), 0x4a.toByte(), 0xaf.toByte(), 0x39.toByte(), 0x78.toByte(), 0x51.toByte(),
//      0x4e.toByte(), 0xf8.toByte(), 0x44.toByte(), 0x3b.toByte(), 0xb2.toByte(), 0xa8.toByte(), 0x59.toByte(), 0xc7.toByte(),
//      0x5f.toByte(), 0xc3.toByte(), 0xcc.toByte(), 0x6a.toByte(), 0xf2.toByte(), 0x6d.toByte(), 0x5a.toByte(), 0xaa.toByte()
//    ) }
//  )
)

class ZBase32Test {
  @Test
  fun `it encodes and decodes`() {
    for (vector in zbase32Vectors) {
      val encoded = ZBase32.encode(vector.decoded())
      assertEquals(vector.encoded, encoded)

      val decoded = ZBase32.decode(encoded)
      assertContentEquals(vector.decoded(), decoded)
    }
  }
}