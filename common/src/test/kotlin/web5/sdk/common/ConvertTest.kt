package web5.sdk.common

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ConvertTest {
  @Nested
  inner class StringTest {
    @Test
    fun toBase64Url_NullKind() {
      val input = "foo";
      val expectedOutput = "Zm9v";

      val output = Convert(input).toBase64Url()
      assertEquals(output, expectedOutput)
    }

    @Test
    fun toBase64Url_Base64Kind() {
      val input = "foo"

      val output = Convert(input, EncodingFormat.Base64Url).toBase64Url()
      assertEquals(input, output)
    }

    @Test
    fun toBase64Url_UnsupportedEncodingFormat() {
      val input = "foo"

      assertFailsWith<UnsupportedOperationException> {
        Convert(input, EncodingFormat.Base58Btc).toBase64Url()
      }
    }

    @Test
    fun toBase64Url_UnsupportedValueType() {
      val input = 1

      assertFailsWith<UnsupportedOperationException> {
        Convert(input, EncodingFormat.Base58Btc).toBase64Url()
      }
    }

    @Test
    fun toBase58Btc_Base58Kind() {
      val input = "foo"

      val output = Convert(input, EncodingFormat.Base58Btc).toBase58Btc()
      assertEquals(input, output)
    }

    @Test
    fun toBase58Btc_Base64Kind() {
      val input = "foo"
      val expectedOutput = "AdX"
      val output = Convert(input, EncodingFormat.Base64Url).toBase58Btc()
      assertEquals(expectedOutput, output)
    }

    @Test
    fun toBase58Btc_ZBase32Kind() {
      val input = "bar"
      val expectedOutput = "F"
      val output = Convert(input, EncodingFormat.ZBase32).toBase58Btc()
      assertEquals(expectedOutput, output)
    }

    @Test
    fun toBase58Btc_NullKind() {
      val input = "foo"
      val expectedOutput = "bQbp"
      val output = Convert(input).toBase58Btc()
      assertEquals(expectedOutput, output)
    }

    @Test
    fun toBase58Btc_UnsupportedValueType() {
      val input = 1

      assertFailsWith<UnsupportedOperationException> {
        Convert(input).toBase58Btc()
      }
    }

    @Test
    fun toZBase32_Base58Kind() {
      val input = "foo"
      val expectedOutput = "y869r"

      val output = Convert(input, EncodingFormat.Base58Btc).toZBase32()
      assertEquals(expectedOutput, output)
    }

    @Test
    fun toZBase32_Base64Kind() {
      val input = "foo"
      val expectedOutput = "x4fy"

      val output = Convert(input, EncodingFormat.Base64Url).toZBase32()
      assertEquals(expectedOutput, output)
    }

    @Test
    fun toZBase32_ZBase32Kind() {
      val input = "foo"
      val output = Convert(input, EncodingFormat.ZBase32).toZBase32()
      assertEquals(input, output)
    }

    @Test
    fun toZBase32_NullKind() {
      val input = "foo"
      val expectedOutput = "c3zs6"
      val output = Convert(input).toZBase32()
      assertEquals(expectedOutput, output)
    }

    @Test
    fun toZBase32_UnsupportedValueType() {
      val input = 1

      assertFailsWith<UnsupportedOperationException> {
        Convert(input).toZBase32()
      }
    }

    @Test
    fun toStr_Base64Kind() {
      val input = "Zm9v"
      val expectedOutput = "foo"
      val output = Convert(input, EncodingFormat.Base64Url).toStr()

      assertEquals(expectedOutput, output)
    }

    @Test
    fun toStr_ZBase32Kind() {
      val input = "c3zs6"
      val expectedOutput = "foo"
      val output = Convert(input, EncodingFormat.ZBase32).toStr()

      assertEquals(expectedOutput, output)
    }

    @Test
    fun toStr_NullKind() {
      val input = "foo"
      val output = Convert(input).toStr()

      assertEquals(input, output)
    }

    @Test
    fun toStr_UnsupportedKind() {
      val input = "foo"

      assertFailsWith<UnsupportedOperationException> {
        Convert(input, EncodingFormat.Base58Btc).toStr()
      }
    }

    @Test
    fun toStr_UnsupportedValueType() {
      val input = 1

      assertFailsWith<UnsupportedOperationException> {
        Convert(input).toStr()
      }
    }

    @Test
    fun toByteArray_Base58Kind() {
      val input = "bQbp"
      val expectedOutput = "foo".toByteArray()
      val output = Convert(input, EncodingFormat.Base58Btc).toByteArray()

      assertArrayEquals(expectedOutput, output)
    }

    @Test
    fun toByteArray_Base64Kind() {
      val input = "Zm9v"
      val expectedOutput = "foo".toByteArray()
      val output = Convert(input, EncodingFormat.Base64Url).toByteArray()

      assertArrayEquals(expectedOutput, output)
    }

    @Test
    fun toByteArray_ZBase32Kind() {
      val input = "c3zs6"
      val expectedOutput = "foo".toByteArray()
      val output = Convert(input, EncodingFormat.ZBase32).toByteArray()

      assertArrayEquals(expectedOutput, output)
    }

    @Test
    fun toByteArray_NullKind() {
      val input = "foo".toByteArray()
      val output = Convert(input).toByteArray()

      assertArrayEquals(input, output)
    }

    @Test
    fun toByteArray_UnsupportedValueKind() {
      val input = 1

      assertFailsWith<UnsupportedOperationException> {
        Convert(input).toByteArray()
      }    }
  }
}