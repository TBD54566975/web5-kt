package web5.sdk.common


import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.random.nextInt

/**
 * tests vectors taken from [here](https://github.com/chrisdickinson/varint/blob/master/test.js).
 * this JS implementation is referenced in
 * the [multiformats unsigned-varint spec](https://github.com/multiformats/unsigned-varint).
 *
 */
class VarintTest {
  @Test
  fun `fuzz test`() {
    repeat(100) {
      val expect = Random.nextInt(0x7FFFFFFF)
      val encoded = Varint.encode(expect)
      val (data, bytesRead) = Varint.decode(encoded)
      assertEquals(expect, data, "fuzz test: $expect")
      assertEquals(encoded.size, bytesRead)
    }
  }

  @Test
  fun `test single byte works as expected`() {
    val buf = byteArrayOf(172.toByte(), 2.toByte())
    val (data, bytesRead) = Varint.decode(buf)
    assertEquals(300, data, "should equal 300")
    assertEquals(2, bytesRead)
  }

  @Test
  fun `test encode works as expected`() {
    assertArrayEquals(byteArrayOf(0xAC.toByte(), 0x02), Varint.encode(300))
  }

  @Test
  fun `test decode single bytes`() {
    val expected = Random.nextInt(0b1111111)
    val buf = byteArrayOf(expected.toByte())
    val (data, bytesRead) = Varint.decode(buf)
    assertEquals(expected, data)
    assertEquals(1, bytesRead)
  }

  @Test
  fun `test decode multiple bytes with zero`() {
    val expected = Random.nextInt(0b1111111)
    val buf = byteArrayOf(128.toByte(), expected.toByte())
    val (data, bytesRead) = Varint.decode(buf)
    assertEquals(expected shl 7, data)
    assertEquals(2, bytesRead)
  }

  @Test
  fun `encode single byte`() {
    val expected = Random.nextInt(0b1111111)
    assertArrayEquals(byteArrayOf(expected.toByte()), Varint.encode(expected))
  }

  @Test
  fun `encode multiple byte with zero first byte`() {
    val expected = 0x0F00
    assertArrayEquals(byteArrayOf(0x80.toByte(), 0x1E.toByte()), Varint.encode(expected))
  }

  @Test
  fun `big integers`() {
    (32..53).map { i ->
      Math.pow(2.0, i.toDouble()) - 1
    }.forEach { n ->
      val data = Varint.encode(n.toInt())
      assertEquals(n.toInt(), Varint.decode(data).first)
      assertNotEquals(n.toInt() - 1, Varint.decode(data).first)
    }
  }

  @Test
  fun `fuzz test - big`() {
    repeat(100) {
      val rando = Random.nextInt(Int.MAX_VALUE - 200..Int.MAX_VALUE)
      val encoded = Varint.encode(rando)
      val (data, bytesRead) = Varint.decode(encoded)
      assertEquals(rando, data, "fuzz test: $rando")
      assertEquals(encoded.size, bytesRead)
    }
  }
}
