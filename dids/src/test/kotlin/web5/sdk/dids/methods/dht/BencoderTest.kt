package web5.sdk.dids.methods.dht

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class BencoderTest {
  @Nested
  inner class Encode {
    @Test
    fun `should encode a list`() {
      val encoded = Bencoder.encode(listOf("spam", "eggs"))
      assertEquals(encoded, "l4:spam4:eggse")
    }

    @Test
    fun `should encode a string`() {
      val encoded = Bencoder.encode("")
      assertEquals(encoded, "0:")
    }

    @Test
    fun `should encode an empty list`() {
      val encoded = Bencoder.encode(emptyList<Any>())
      assertEquals(encoded, "le")
    }

    @Test
    fun `should encode a dictionary`() {
      val encoded = Bencoder.encode(mapOf("cow" to "moo", "spam" to "eggs"))
      assertEquals(encoded, "d3:cow3:moo4:spam4:eggse")
    }

    @Test
    fun `should encode empty dictionary`() {
      val encoded = Bencoder.encode(emptyMap<Any, Any>())
      assertEquals(encoded, "de")
    }
  }

  @Nested
  inner class EncodeAsBytes {
    @Test
    fun `encode an empty byte array`() {
      val input = ByteArray(0)
      val expected = "0:".toByteArray()
      val result = Bencoder.encodeAsBytes(input)
      assertArrayEquals(expected, result)
    }

    @Test
    fun `encode a byte array with a single byte`() {
      val input = byteArrayOf(65)
      val expected = "1:A".toByteArray()
      val result = Bencoder.encodeAsBytes(input)
      assertArrayEquals(expected, result)
    }

    @Test
    fun `encode a byte array with multiple bytes`() {
      val input = byteArrayOf(65, 66, 67)
      val expected = "3:ABC".toByteArray()
      val result = Bencoder.encodeAsBytes(input)
      assertArrayEquals(expected, result)
    }

    @Test
    fun `encode a byte array with special characters`() {
      val input = byteArrayOf(35, 36, 37)
      val expected = "3:#$%".toByteArray()
      val result = Bencoder.encodeAsBytes(input)
      assertArrayEquals(expected, result)
    }

    @Test
    fun `encode a very large byte array`() {
      val input = ByteArray(1_000_000) { 65 }
      val expected = "1000000:${"A".repeat(1_000_000)}".toByteArray()
      val result = Bencoder.encodeAsBytes(input)
      assertArrayEquals(expected, result)
    }
  }

  @Nested
  inner class Decode {
    @Test
    fun `should decode a dictionary string`() {
      val encoded = "d9:publisher3:bob17:publisher-webpage15:www.example.com18:publisher.location4:homee"
      val (result, _) = Bencoder.decode(encoded)
      val expected = mapOf(
        "publisher" to "bob",
        "publisher-webpage" to "www.example.com",
        "publisher.location" to "home"
      )
      assertEquals(result, expected)
    }
  }
}